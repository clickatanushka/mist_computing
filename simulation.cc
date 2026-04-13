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
    // which rules to enforce
    bool   check_rate    = true;
    bool   check_jitter  = true;
    bool   check_latency = true;
    bool   check_payload = false;
    bool   check_entropy = false;
};

// ── Simple JSON value extractor (no external library needed) ─
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

// ── Profile loader from ids_profiles.json ────────────────────
// Loads the block:  profiles[attack][layer]
// Returns fallback if file or block is missing.
ThresholdProfile loadProfile(const std::string& attack,
                              const std::string& layer) {
    ThresholdProfile p;
    std::ifstream f("ids_profiles.json");
    if (!f.is_open()) return p;   // file missing → use defaults

    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    // find the attack block
    size_t aPos = json.find("\"" + attack + "\"");
    if (aPos == std::string::npos) return p;

    // find the layer block inside the attack block
    size_t lPos = json.find("\"" + layer + "\"", aPos);
    if (lPos == std::string::npos) return p;

    // extract the { ... } block for this layer
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

    // always check rate for all modes (safety net)
    p.check_rate    = true;
    p.check_jitter  = (primary == "jitter"  || secondary == "jitter");
    p.check_latency = (primary == "latency" || secondary == "latency");
    p.check_payload = (primary == "payload" || secondary == "payload");
    p.check_entropy = (primary == "entropy" || secondary == "entropy");

    return p;
}

// ── ModeChange control message ───────────────────────────────
class ModeChangeMsg : public cMessage {
  public:
    ThreatMode newMode;
    ModeChangeMsg(ThreatMode m) : cMessage("ModeChange"), newMode(m) {}
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CentralController
//  ─────────────────
//  Observes aggregate traffic metrics from a shared scalar
//  (updated by EdgeNode every second) and decides which
//  ThreatMode is active, then broadcasts ModeChange to all
//  layers via direct sendDirect().
//
//  Classification logic (lightweight, no ML library needed in
//  OMNeT++; the Python model does the heavy lifting offline and
//  the thresholds it produces are already in the JSON):
//
//  DDOS:  windowRate > ddos_rate_trigger
//  MITM:  latencySpike detected (latency > 2×baseline)
//  SQLI:  payload size anomaly (avgPayload > sqli_payload_trigger)
//  → defaults to DDOS mode if ambiguous (most dangerous)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CentralController : public cSimpleModule {
  private:
    ThreatMode currentMode = MODE_DDOS;
    simtime_t  lastSwitch  = 0;
    int        switchCount = 0;

    // observation window (updated via signals from EdgeNode)
    double obsRate        = 0;
    double obsLatency     = 0;
    double obsPayload     = 0;
    double obsJitter      = 0;

    // trigger thresholds (conservative — switching is costly)
    const double DDOS_RATE_TRIGGER    = 8.0;   // pkt/s aggregate
    const double MITM_LATENCY_TRIGGER = 0.15;  // seconds
    const double SQLI_PAYLOAD_TRIGGER = 400.0; // bytes

    cMessage *scanTimer = nullptr;

  protected:
    virtual void initialize() override {
        EV << "[Controller] Starting in DDOS mode (default)\n";
        scanTimer = new cMessage("scanTimer");
        scheduleAt(simTime() + 2, scanTimer);  // first evaluation at t=2
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "EdgeReport") == 0) {
            // EdgeNode sends us an observation every second
            obsRate    = msg->par("rate").doubleValue();
            obsLatency = msg->par("latency").doubleValue();
            obsPayload = msg->par("payload").doubleValue();
            obsJitter  = msg->par("jitter").doubleValue();
            delete msg;
            return;
        }

        if (strcmp(msg->getName(), "scanTimer") == 0) {
            classifyAndSwitch();
            scheduleAt(simTime() + 1, msg);   // re-evaluate every second
            return;
        }
        delete msg;
    }

    void classifyAndSwitch() {
        ThreatMode detected = detectMode();
        if (detected != currentMode) {
            EV << "[Controller] t=" << simTime()
               << " Mode switch: " << modeName(currentMode)
               << " → " << modeName(detected) << "\n";
            currentMode = detected;
            switchCount++;
            lastSwitch  = simTime();
            broadcastMode(detected);
            recordScalar("Controller mode switch at", simTime().dbl());
        }
    }

    ThreatMode detectMode() {
        // Priority: MitM < SQLi < DDoS (most dangerous first)
        if (obsRate > DDOS_RATE_TRIGGER)
            return MODE_DDOS;
        if (obsPayload > SQLI_PAYLOAD_TRIGGER)
            return MODE_SQLI;
        if (obsLatency > MITM_LATENCY_TRIGGER)
            return MODE_MITM;
        return currentMode;   // no change if below all triggers
    }

    void broadcastMode(ThreatMode m) {
        // send to all layers by name — adjust to your NED topology
        const char* targets[] = {
            "edge[0]","edge[1]","edge[2]",
            "mist[0]","mist[1]",
            "fog",
            "cloud",
            nullptr
        };
        for (int i = 0; targets[i]; i++) {
            cModule *mod = getModuleByPath(targets[i]);
            if (mod) {
                ModeChangeMsg *ctrl = new ModeChangeMsg(m);
                sendDirect(ctrl, mod, "controlIn");
            }
        }
        EV << "[Controller] Broadcast mode=" << modeName(m) << "\n";
    }

    virtual void finish() override {
        recordScalar("Controller total switches", switchCount);
        recordScalar("Controller final mode",     (int)currentMode);
    }
};
Define_Module(CentralController);


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  IoTNode — unchanged from before except:
//   • iot[0] sends DDoS flood after t=5  (same as before)
//   • iot[1] sends large payloads after t=15  (SQLi simulation)
//   • iot[2] sends with artificial delay after t=25 (MitM sim)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class IoTNode : public cSimpleModule {
  private:
    int  packetCount  = 0;
    bool isDDoS       = false;
    bool isSQLi       = false;
    bool isMITM       = false;

  protected:
    virtual void initialize() override {
        isDDoS = (getIndex() == 0);
        isSQLi = (getIndex() == 1);
        isMITM = (getIndex() == 2);
        scheduleAt(simTime() + 1, new cMessage("timer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        // reply from Edge
        if (strcmp(msg->getName(), "SensorData") == 0) {
            EV << "IoT[" << getIndex() << "] RTT="
               << (simTime() - msg->getTimestamp()) << "\n";
            delete msg;
            return;
        }

        // ── normal packet ──
        packetCount++;
        sendSensorPacket(64.0, false);   // 64-byte normal packet
        scheduleAt(simTime() + 1, msg);

        // ── DDoS flood (iot[0] after t=5) ──
        if (isDDoS && simTime() >= 5) {
            for (int i = 0; i < 9; i++)
                sendSensorPacket(64.0, true);
            EV << "ATTACKER[DDoS] flood at t=" << simTime() << "\n";
        }

        // ── SQLi large payload (iot[1] after t=15) ──
        if (isSQLi && simTime() >= 15) {
            sendSensorPacket(1200.0, true);   // oversized payload
            EV << "ATTACKER[SQLi] large-payload at t=" << simTime() << "\n";
        }

        // ── MitM artificial latency (iot[2] after t=25) ──
        // we simulate by injecting a delayed duplicate
        if (isMITM && simTime() >= 25) {
            cMessage *delayed = new cMessage("SensorData");
            delayed->setTimestamp(simTime() - 0.5);  // fake 500ms-old stamp
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
//  Base class for all IDS layers
//  Holds 3 profiles (one per mode), switches on ModeChange,
//  and provides common detection helpers.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class IDSLayerBase : public cSimpleModule {
  protected:
    // ── state ──
    ThreatMode    activeMode    = MODE_DDOS;
    ThresholdProfile profiles[3];   // indexed by ThreatMode

    // ── traffic stats ──
    int       totalPackets    = 0;
    int       droppedPackets  = 0;
    int       acceptedPackets = 0;
    simtime_t lastLatency     = 0;
    bool      hasPrior        = false;
    double    sumLatency      = 0;
    double    sumJitter       = 0;

    // ── IDS counters ──
    int idsAlerts   = 0;
    int rateDrops   = 0;
    int jitterDrops = 0;
    int latencyDrops= 0;
    int payloadDrops= 0;
    int entropyDrops= 0;

    // ── rate window ──
    int       windowCount  = 0;
    simtime_t windowStart  = 0;

    // ── active profile shortcut ──
    ThresholdProfile& P() { return profiles[(int)activeMode]; }

    // Load all 3 profiles from JSON for this layer
    void loadProfiles(const std::string& layerName) {
        const char* attacks[] = {"DDOS","MITM","SQLI"};
        for (int i = 0; i < 3; i++)
            profiles[i] = loadProfile(attacks[i], layerName);
    }

    // Handle mode-switch control message
    void applyModeChange(ModeChangeMsg *ctrl) {
        ThreatMode prev = activeMode;
        activeMode = ctrl->newMode;
        if (activeMode != prev)
            EV << "[" << getName() << "] Mode → "
               << modeName(activeMode) << " at t=" << simTime() << "\n";
        delete ctrl;
    }

    // Compute current-window rate; returns true if rate exceeded
    bool rateCheck() {
        if (simTime() - windowStart >= 1) {
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
        // Entropy proxy: high jitter during a burst
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

    // Update latency / jitter bookkeeping
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
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class EdgeNode : public IDSLayerBase {
  private:
    int forwardedPackets = 0;
    int localPackets     = 0;
    simtime_t lastReport = 0;

    // observations to report to controller
    double obsRate = 0, obsLatency = 0,
           obsPayload = 0, obsJitter = 0;

  protected:
    virtual void initialize() override {
        loadProfiles("edge");
        scheduleAt(simTime() + 1, new cMessage("reportTimer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        // ── control plane ──
        if (msg->arrivedOn("controlIn")) {
            applyModeChange((ModeChangeMsg*)msg);
            return;
        }
        if (msg->arrivedOn("fromMIST")) {
            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
            return;
        }
        if (strcmp(msg->getName(), "reportTimer") == 0) {
            reportToController();
            scheduleAt(simTime() + 1, msg);
            return;
        }

        // ── data plane ──
        simtime_t latency, jitter;
        updateMetrics(msg, latency, jitter);

        obsLatency = latency.dbl();
        obsJitter  = jitter.dbl();
        if (msg->hasPar("payloadSize"))
            obsPayload = msg->par("payloadSize").doubleValue();

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
        cModule *ctrl = getModuleByPath("controller");
        if (!ctrl) return;
        cMessage *rpt = new cMessage("EdgeReport");
        rpt->addPar("rate")    = (double)windowCount;
        rpt->addPar("latency") = obsLatency;
        rpt->addPar("payload") = obsPayload;
        rpt->addPar("jitter")  = obsJitter;
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
            send(msg, "toEdge", msg->getArrivalGate()->getIndex());
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
//  CloudNode — Layer 4 IDS (most comprehensive)
//  Extra rule: throughput-spike anomaly (EMA based)
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

        // throughput spike (with warm-up guard)
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
