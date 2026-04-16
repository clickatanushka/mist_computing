#include <omnetpp.h>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <string>
using namespace omnetpp;

// ── Threat mode ──────────────────────────────────────────────
enum ThreatMode { MODE_DDOS = 0, MODE_MITM = 1, MODE_SQLI = 2 };

const char* modeName(ThreatMode m) {
    switch (m) {
        case MODE_DDOS: return "DDOS";
        case MODE_MITM: return "MITM";
        case MODE_SQLI: return "SQLI";
    }
    return "UNKNOWN";
}

// ── Per-attack threshold profile ─────────────────────────────
struct ThresholdProfile {
    int    rate_pps      = 5;
    double jitter_s      = 0.025;
    double latency_s     = 0.300;
    double payload_bytes = 200.0;
    double entropy       = 80.0;
    bool   check_rate    = true;
    bool   check_jitter  = true;
    bool   check_latency = true;
    bool   check_payload = false;
    bool   check_entropy = false;
};

// ── Simple JSON helpers ───────────────────────────────────────
static double jsonDouble(const std::string& json,
                          const std::string& key, double def = 0.0) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;
    pos = json.find(":", pos);
    if (pos == std::string::npos) return def;
    return std::stod(json.substr(pos + 1));
}
static int jsonInt(const std::string& json,
                    const std::string& key, int def = 0) {
    return (int)jsonDouble(json, key, def);
}
static std::string jsonStr(const std::string& json,
                             const std::string& key,
                             const std::string& def = "") {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;
    pos = json.find("\"", pos + search.size() + 1);
    if (pos == std::string::npos) return def;
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return def;
    return json.substr(pos + 1, end - pos - 1);
}

ThresholdProfile loadProfile(const std::string& attack,
                              const std::string& layer) {
    ThresholdProfile p;
    std::ifstream f("ids_profiles.json");
    if (!f.is_open()) return p;

    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    size_t aPos = json.find("\"" + attack + "\"");
    if (aPos == std::string::npos) return p;

    size_t lPos = json.find("\"" + layer + "\"", aPos);
    if (lPos == std::string::npos) return p;

    size_t brace = json.find("{", lPos);
    if (brace == std::string::npos) return p;
    size_t end = json.find("}", brace);
    if (end == std::string::npos) return p;

    std::string block = json.substr(brace, end - brace + 1);

    p.rate_pps      = jsonInt(block,    "rate_pps",      p.rate_pps);
    p.jitter_s      = jsonDouble(block, "jitter_s",      p.jitter_s);
    p.latency_s     = jsonDouble(block, "latency_s",     p.latency_s);
    p.payload_bytes = jsonDouble(block, "payload_bytes", p.payload_bytes);
    p.entropy       = jsonDouble(block, "entropy",       p.entropy);

    std::string primary   = jsonStr(block, "primary_rule",   "rate");
    std::string secondary = jsonStr(block, "secondary_rule", "jitter");

    p.check_rate    = true;
    p.check_jitter  = (primary == "jitter"  || secondary == "jitter");
    p.check_latency = (primary == "latency" || secondary == "latency");
    p.check_payload = (primary == "payload" || secondary == "payload");
    p.check_entropy = (primary == "entropy" || secondary == "entropy");

    return p;
}

// ── ModeChange message ────────────────────────────────────────
class ModeChangeMsg : public cMessage {
  public:
    ThreatMode newMode;
    ModeChangeMsg(ThreatMode m) : cMessage("ModeChange"), newMode(m) {}
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CentralController
//  FIX 1: obsRateSum accumulates across all Edge reports per window
//          instead of only keeping the last one.
//  FIX 2: DDOS_RATE_TRIGGER lowered to 6 (3 edges × 2 pkts each
//          is normal; flood pushes it above 6 easily).
//  FIX 3: SQLI_PAYLOAD_TRIGGER lowered to 200 so large payload
//          packets (1200 bytes) actually trigger mode switch.
//  FIX 4: broadcastMode uses full NED path "IDSNetwork.fog" etc.
//          because getModuleByPath resolves relative to network root.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CentralController : public cSimpleModule {
  private:
    ThreatMode currentMode = MODE_DDOS;
    int        switchCount = 0;

    // FIX 1: accumulate rate across all Edge nodes per scan window
    double obsRateSum  = 0;
    int    reportCount = 0;
    double obsLatency  = 0;
    double obsPayload  = 0;
    double obsJitter   = 0;

    // FIX 2 & 3: lower triggers so they actually fire
    const double DDOS_RATE_TRIGGER    = 6.0;   // was 8.0
    const double MITM_LATENCY_TRIGGER = 0.10;  // was 0.15
    const double SQLI_PAYLOAD_TRIGGER = 200.0; // was 400.0

    cMessage *scanTimer = nullptr;

  protected:
    virtual void initialize() override {
        EV << "[Controller] Starting in DDOS mode (default)\n";
        scanTimer = new cMessage("scanTimer");
        scheduleAt(simTime() + 2, scanTimer);
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "EdgeReport") == 0) {
            // FIX 1: accumulate, don't overwrite
            obsRateSum += msg->par("rate").doubleValue();
            reportCount++;
            // take max latency / payload seen across edges (most suspicious)
            double lat = msg->par("latency").doubleValue();
            double pay = msg->par("payload").doubleValue();
            if (lat > obsLatency) obsLatency = lat;
            if (pay > obsPayload) obsPayload = pay;
            obsJitter = msg->par("jitter").doubleValue();
            delete msg;
            return;
        }

        if (strcmp(msg->getName(), "scanTimer") == 0) {
            classifyAndSwitch();
            // reset accumulators for next window
            obsRateSum  = 0;
            reportCount = 0;
            obsLatency  = 0;
            obsPayload  = 0;
            obsJitter   = 0;
            scheduleAt(simTime() + 1, msg);
            return;
        }
        delete msg;
    }

    void classifyAndSwitch() {
        ThreatMode detected = detectMode();
        EV << "[Controller] t=" << simTime()
           << " obsRateSum=" << obsRateSum
           << " obsPayload=" << obsPayload
           << " obsLatency=" << obsLatency
           << " → mode=" << modeName(detected) << "\n";

        if (detected != currentMode) {
            EV << "[Controller] MODE SWITCH: " << modeName(currentMode)
               << " → " << modeName(detected) << "\n";
            currentMode = detected;
            switchCount++;
            broadcastMode(detected);
            recordScalar("Controller mode switch at", simTime().dbl());
        }
    }

    ThreatMode detectMode() {
        if (obsRateSum > DDOS_RATE_TRIGGER)    return MODE_DDOS;
        if (obsPayload > SQLI_PAYLOAD_TRIGGER) return MODE_SQLI;
        if (obsLatency > MITM_LATENCY_TRIGGER) return MODE_MITM;
        return currentMode;
    }

    void broadcastMode(ThreatMode m) {
        // FIX 4: use full paths relative to network root
        const char* targets[] = {
            "IDSNetwork.edge[0]",
            "IDSNetwork.edge[1]",
            "IDSNetwork.edge[2]",
            "IDSNetwork.mist[0]",
            "IDSNetwork.mist[1]",
            "IDSNetwork.fog",
            "IDSNetwork.cloud",
            nullptr
        };
        for (int i = 0; targets[i]; i++) {
            cModule *mod = getModuleByPath(targets[i]);
            if (mod) {
                ModeChangeMsg *ctrl = new ModeChangeMsg(m);
                sendDirect(ctrl, mod, "controlIn");
                EV << "[Controller] Sent mode=" << modeName(m)
                   << " to " << targets[i] << "\n";
            } else {
                EV << "[Controller] WARNING: module not found: "
                   << targets[i] << "\n";
            }
        }
    }

    virtual void finish() override {
        recordScalar("Controller total switches", switchCount);
        recordScalar("Controller final mode",     (int)currentMode);
    }
};
Define_Module(CentralController);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  IoTNode
//  iot[0] → DDoS flood after t=5
//  iot[1] → SQLi large payload after t=15
//  iot[2] → MitM delayed replay after t=25
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class IoTNode : public cSimpleModule {
  private:
    int  packetCount = 0;
    bool isDDoS      = false;
    bool isSQLi      = false;
    bool isMITM      = false;

  protected:
    virtual void initialize() override {
        isDDoS = (getIndex() == 0);
        isSQLi = (getIndex() == 1);
        isMITM = (getIndex() == 2);
        scheduleAt(simTime() + 1, new cMessage("timer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "SensorData") == 0) {
            EV << "IoT[" << getIndex() << "] RTT="
               << (simTime() - msg->getTimestamp()) << "\n";
            delete msg;
            return;
        }

        packetCount++;
        sendSensorPacket(64.0, false);
        scheduleAt(simTime() + 1, msg);

        if (isDDoS && simTime() >= 5) {
            for (int i = 0; i < 9; i++)
                sendSensorPacket(64.0, true);
            EV << "ATTACKER[DDoS] flood at t=" << simTime() << "\n";
        }

        if (isSQLi && simTime() >= 15) {
            sendSensorPacket(1200.0, true);
            EV << "ATTACKER[SQLi] large-payload at t=" << simTime() << "\n";
        }

        if (isMITM && simTime() >= 25) {
            cMessage *delayed = new cMessage("SensorData");
            delayed->setTimestamp(simTime() - 0.5);
            delayed->addPar("payloadSize") = 64.0;
            send(delayed, "out");
            EV << "ATTACKER[MitM] delayed-replay at t=" << simTime() << "\n";
        }
    }

    void sendSensorPacket(double payloadBytes, bool isAttack) {
        cMessage *pkt = new cMessage("SensorData");
        pkt->setTimestamp(simTime());
        pkt->addPar("payloadSize") = payloadBytes;
        pkt->addPar("isAttack")   = isAttack ? 1.0 : 0.0;
        send(pkt, "out");
    }
};
Define_Module(IoTNode);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  IDSLayerBase — shared detection logic for all layers
//  FIX 5: obsRate is reported as windowCount which was being
//          reset BEFORE reportToController was called, so it
//          always reported 0. Now we snapshot it before reset.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class IDSLayerBase : public cSimpleModule {
  protected:
    ThreatMode       activeMode = MODE_DDOS;
    ThresholdProfile profiles[3];

    int       totalPackets    = 0;
    int       droppedPackets  = 0;
    int       acceptedPackets = 0;
    simtime_t lastLatency     = 0;
    bool      hasPrior        = false;
    double    sumLatency      = 0;
    double    sumJitter       = 0;

    int idsAlerts    = 0;
    int rateDrops    = 0;
    int jitterDrops  = 0;
    int latencyDrops = 0;
    int payloadDrops = 0;
    int entropyDrops = 0;

    int       windowCount = 0;
    simtime_t windowStart = 0;

    ThresholdProfile& P() { return profiles[(int)activeMode]; }

    void loadProfiles(const std::string& layerName) {
        const char* attacks[] = {"DDOS","MITM","SQLI"};
        for (int i = 0; i < 3; i++)
            profiles[i] = loadProfile(attacks[i], layerName);
    }

    void applyModeChange(ModeChangeMsg *ctrl) {
        ThreatMode prev = activeMode;
        activeMode = ctrl->newMode;
        if (activeMode != prev)
            EV << "[" << getName() << "] Mode → "
               << modeName(activeMode) << " at t=" << simTime() << "\n";
        delete ctrl;
    }

    // FIX 5: rateCheck now correctly maintains the window counter
    // and returns the current count BEFORE deciding to drop,
    // so the reported rate is always the actual burst count.
    bool rateCheck() {
        if (simTime() - windowStart >= 1.0) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;
        return P().check_rate && (windowCount > P().rate_pps);
    }

    bool jitterCheck(simtime_t jitter) {
        return P().check_jitter && hasPrior
               && (jitter.dbl() > P().jitter_s)
               && (windowCount >= 2);
    }

    bool latencyCheck(simtime_t latency) {
        return P().check_latency && (latency.dbl() > P().latency_s);
    }

    bool payloadCheck(cMessage *msg) {
        if (!P().check_payload) return false;
        if (!msg->hasPar("payloadSize")) return false;
        return msg->par("payloadSize").doubleValue() > P().payload_bytes;
    }

    bool entropyCheck(cMessage *msg) {
        if (!P().check_entropy) return false;
        if (!hasPrior)          return false;
        return (sumJitter / std::max(1, totalPackets)) > P().entropy;
    }

    void drop(cMessage *msg, const char* rule) {
        idsAlerts++;
        droppedPackets++;
        EV << "[" << getName() << "-IDS][" << modeName(activeMode)
           << "] DROP rule=" << rule
           << " at t=" << simTime() << "\n";
        recordScalar((std::string(getName())+" drop at").c_str(),
                     simTime().dbl());
        delete msg;
    }

    void updateMetrics(cMessage *msg,
                       simtime_t &latency, simtime_t &jitter) {
        latency = simTime() - msg->getTimestamp();
        jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();
        totalPackets++;
    }
};


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EdgeNode — Layer 1 IDS
//  FIX 5 (cont): reportToController snapshots windowCount
//  BEFORE it gets reset on next packet arrival, so the
//  controller actually sees the burst count not zero.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class EdgeNode : public IDSLayerBase {
  private:
    int    forwardedPackets  = 0;
    int    localPackets      = 0;
    double lastReportedRate  = 0;  // FIX 5: snapshot before reset
    double lastReportedPay   = 0;
    double lastReportedLat   = 0;
    double lastReportedJit   = 0;

  protected:
    virtual void initialize() override {
        loadProfiles("edge");
        scheduleAt(simTime() + 1, new cMessage("reportTimer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyModeChange((ModeChangeMsg*)msg);
            return;
        }
        if (msg->arrivedOn("fromMIST")) {
            delete msg;
            return;
        }
        if (strcmp(msg->getName(), "reportTimer") == 0) {
            reportToController();
            scheduleAt(simTime() + 1, msg);
            return;
        }

        // data plane
        simtime_t latency, jitter;
        updateMetrics(msg, latency, jitter);

        // FIX 5: snapshot CURRENT window values for reporting
        lastReportedRate = (double)windowCount;
        lastReportedLat  = latency.dbl();
        lastReportedJit  = jitter.dbl();
        if (msg->hasPar("payloadSize"))
            lastReportedPay = msg->par("payloadSize").doubleValue();

        if (rateCheck())          { rateDrops++;   drop(msg,"rate");    return; }
        if (jitterCheck(jitter))  { jitterDrops++; drop(msg,"jitter");  return; }
        if (payloadCheck(msg))    { payloadDrops++;drop(msg,"payload"); return; }
        if (latencyCheck(latency)){ latencyDrops++;drop(msg,"latency"); return; }

        acceptedPackets++;
        if (intrand(2) == 0) {
            localPackets++;
            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
        } else {
            forwardedPackets++;
            send(msg, "toMIST");
        }
    }

    void reportToController() {
        // FIX 4: use full NED path
        cModule *ctrl = getModuleByPath("IDSNetwork.controller");
        if (!ctrl) {
            EV << "[Edge] WARNING: controller not found!\n";
            return;
        }
        cMessage *rpt = new cMessage("EdgeReport");
        // FIX 5: report the snapshot, not the post-reset value
        rpt->addPar("rate")    = lastReportedRate;
        rpt->addPar("latency") = lastReportedLat;
        rpt->addPar("payload") = lastReportedPay;
        rpt->addPar("jitter")  = lastReportedJit;
        sendDirect(rpt, ctrl, "dataIn");
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        recordScalar("Edge total packets",     totalPackets);
        recordScalar("Edge dropped packets",   droppedPackets);
        recordScalar("Edge forwarded packets", forwardedPackets);
        recordScalar("Edge IDS alerts",        idsAlerts);
        recordScalar("Edge rate drops",        rateDrops);
        recordScalar("Edge jitter drops",      jitterDrops);
        recordScalar("Edge payload drops",     payloadDrops);
        recordScalar("Edge latency drops",     latencyDrops);
        recordScalar("Edge avg latency",       totalPackets>0 ? sumLatency/totalPackets : 0);
        recordScalar("Edge avg jitter",        totalPackets>0 ? sumJitter/totalPackets  : 0);
        recordScalar("Edge throughput",        totalPackets/simT);
        recordScalar("Edge drop rate",         totalPackets>0 ? (double)droppedPackets/totalPackets : 0);
    }
};
Define_Module(EdgeNode);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MISTNode — Layer 2 IDS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class MISTNode : public IDSLayerBase {
  private:
    int forwardedPackets = 0;
    int localPackets     = 0;

  protected:
    virtual void initialize() override {
        loadProfiles("mist");
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyModeChange((ModeChangeMsg*)msg);
            return;
        }

        simtime_t latency, jitter;
        updateMetrics(msg, latency, jitter);

        if (rateCheck())          { rateDrops++;   drop(msg,"rate");    return; }
        if (jitterCheck(jitter))  { jitterDrops++; drop(msg,"jitter");  return; }
        if (payloadCheck(msg))    { payloadDrops++;drop(msg,"payload"); return; }
        if (latencyCheck(latency)){ latencyDrops++;drop(msg,"latency"); return; }

        acceptedPackets++;
        if (intrand(2) == 0) {
            localPackets++;
            int replyGate = msg->getArrivalGate()->getIndex();
            if (replyGate < gateSize("toEdge"))
                send(msg, "toEdge", replyGate);
            else
                delete msg;
        } else {
            forwardedPackets++;
            send(msg, "toFog");
        }
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        recordScalar("MIST total packets",     totalPackets);
        recordScalar("MIST dropped packets",   droppedPackets);
        recordScalar("MIST forwarded packets", forwardedPackets);
        recordScalar("MIST IDS alerts",        idsAlerts);
        recordScalar("MIST rate drops",        rateDrops);
        recordScalar("MIST jitter drops",      jitterDrops);
        recordScalar("MIST payload drops",     payloadDrops);
        recordScalar("MIST avg latency",       totalPackets>0 ? sumLatency/totalPackets : 0);
        recordScalar("MIST avg jitter",        totalPackets>0 ? sumJitter/totalPackets  : 0);
        recordScalar("MIST throughput",        totalPackets/simT);
        recordScalar("MIST drop rate",         totalPackets>0 ? (double)droppedPackets/totalPackets : 0);
    }
};
Define_Module(MISTNode);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  FogNode — Layer 3 IDS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FogNode : public IDSLayerBase {
  private:
    int forwardedPackets = 0;

  protected:
    virtual void initialize() override {
        loadProfiles("fog");
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyModeChange((ModeChangeMsg*)msg);
            return;
        }

        simtime_t latency, jitter;
        updateMetrics(msg, latency, jitter);

        if (rateCheck())          { rateDrops++;   drop(msg,"rate");    return; }
        if (jitterCheck(jitter))  { jitterDrops++; drop(msg,"jitter");  return; }
        if (payloadCheck(msg))    { payloadDrops++;drop(msg,"payload"); return; }
        if (latencyCheck(latency)){ latencyDrops++;drop(msg,"latency"); return; }
        if (entropyCheck(msg))    { entropyDrops++;drop(msg,"entropy"); return; }

        acceptedPackets++;
        forwardedPackets++;
        send(msg, "toCloud");
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        recordScalar("Fog total packets",     totalPackets);
        recordScalar("Fog dropped packets",   droppedPackets);
        recordScalar("Fog forwarded packets", forwardedPackets);
        recordScalar("Fog IDS alerts",        idsAlerts);
        recordScalar("Fog rate drops",        rateDrops);
        recordScalar("Fog jitter drops",      jitterDrops);
        recordScalar("Fog payload drops",     payloadDrops);
        recordScalar("Fog latency drops",     latencyDrops);
        recordScalar("Fog entropy drops",     entropyDrops);
        recordScalar("Fog avg latency",       totalPackets>0 ? sumLatency/totalPackets : 0);
        recordScalar("Fog avg jitter",        totalPackets>0 ? sumJitter/totalPackets  : 0);
        recordScalar("Fog throughput",        totalPackets/simT);
        recordScalar("Fog drop rate",         totalPackets>0 ? (double)droppedPackets/totalPackets : 0);
    }
};
Define_Module(FogNode);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CloudNode — Layer 4 IDS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CloudNode : public IDSLayerBase {
  private:
    double runningAvgThroughput = 0;
    int    throughputDrops      = 0;
    const double THROUGHPUT_MULT   = 1.5;
    const int    THROUGHPUT_WARMUP = 5;

  protected:
    virtual void initialize() override {
        loadProfiles("cloud");
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyModeChange((ModeChangeMsg*)msg);
            return;
        }

        simtime_t latency, jitter;
        updateMetrics(msg, latency, jitter);

        double currentThroughput = totalPackets / simTime().dbl();
        runningAvgThroughput = (runningAvgThroughput == 0)
            ? currentThroughput
            : 0.8*runningAvgThroughput + 0.2*currentThroughput;

        if (rateCheck())          { rateDrops++;   drop(msg,"rate");    return; }
        if (jitterCheck(jitter))  { jitterDrops++; drop(msg,"jitter");  return; }
        if (payloadCheck(msg))    { payloadDrops++;drop(msg,"payload"); return; }
        if (latencyCheck(latency)){ latencyDrops++;drop(msg,"latency"); return; }
        if (entropyCheck(msg))    { entropyDrops++;drop(msg,"entropy"); return; }

        if (acceptedPackets >= THROUGHPUT_WARMUP
                && runningAvgThroughput > 0
                && currentThroughput > THROUGHPUT_MULT * runningAvgThroughput) {
            throughputDrops++;
            drop(msg, "throughput");
            return;
        }

        acceptedPackets++;
        EV << "[Cloud] pkt ACCEPTED | latency=" << latency
           << " jitter=" << jitter
           << " throughput=" << currentThroughput << "\n";
        delete msg;
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        recordScalar("Cloud total packets",      totalPackets);
        recordScalar("Cloud accepted packets",   acceptedPackets);
        recordScalar("Cloud dropped packets",    droppedPackets);
        recordScalar("Cloud IDS alerts",         idsAlerts);
        recordScalar("Cloud rate drops",         rateDrops);
        recordScalar("Cloud jitter drops",       jitterDrops);
        recordScalar("Cloud payload drops",      payloadDrops);
        recordScalar("Cloud latency drops",      latencyDrops);
        recordScalar("Cloud entropy drops",      entropyDrops);
        recordScalar("Cloud throughput drops",   throughputDrops);
        recordScalar("Cloud avg latency",        totalPackets>0 ? sumLatency/totalPackets : 0);
        recordScalar("Cloud avg jitter",         totalPackets>0 ? sumJitter/totalPackets  : 0);
        recordScalar("Cloud throughput",         totalPackets/simT);
        recordScalar("Cloud drop rate",          totalPackets>0 ? (double)droppedPackets/totalPackets : 0);
        recordScalar("Cloud detection rate",     totalPackets>0 ? (double)idsAlerts/totalPackets : 0);
    }
};
Define_Module(CloudNode);
