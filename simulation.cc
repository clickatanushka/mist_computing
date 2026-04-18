#include <omnetpp.h>
#include <cmath>
using namespace omnetpp;

// ─────────────────────────────────────────────────────────────
//  Threat modes
// ─────────────────────────────────────────────────────────────
enum ThreatMode { MODE_NORMAL = 0, MODE_DDOS = 1, MODE_SQLI = 2, MODE_MITM = 3 };

const char* modeName(ThreatMode m) {
    switch(m) {
        case MODE_NORMAL: return "NORMAL";
        case MODE_DDOS:   return "DDOS";
        case MODE_SQLI:   return "SQLI";
        case MODE_MITM:   return "MITM";
    }
    return "UNKNOWN";
}

// ─────────────────────────────────────────────────────────────
//  ModeChange message sent from controller to all layers
// ─────────────────────────────────────────────────────────────
class ModeChangeMsg : public cMessage {
  public:
    ThreatMode newMode;
    ModeChangeMsg(ThreatMode m) : cMessage("ModeChange"), newMode(m) {}
};


// ═════════════════════════════════════════════════════════════
//  CentralController
//  - Receives EdgeReports every second from all 3 edge nodes
//  - Accumulates rate, payload, latency BEFORE deciding
//  - Resets AFTER deciding (was the main bug before)
//  - Broadcasts mode to all layers via getSystemModule()
// ═════════════════════════════════════════════════════════════
class CentralController : public cSimpleModule {
  private:
    ThreatMode currentMode = MODE_NORMAL;
    int switchCount = 0;

    double rateSum    = 0;
    double maxPayload = 0;
    double maxLatency = 0;


    const double DDOS_RATE_THRESH    = 8.0;   // sum across edges
    const double SQLI_PAYLOAD_THRESH = 500.0; // bytes
    const double MITM_LATENCY_THRESH = 0.40;  // seconds (normal=0.005s)

  protected:
    virtual void initialize() override {
        EV << "[Controller] Initialized. Mode=NORMAL\n";
        scheduleAt(simTime() + 1, new cMessage("scan"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "EdgeReport") == 0) {
            rateSum    += msg->par("rate").doubleValue();
            double p    = msg->par("payload").doubleValue();
            double l    = msg->par("latency").doubleValue();
            if (p > maxPayload) maxPayload = p;
            if (l > maxLatency) maxLatency = l;
            delete msg;
            return;
        }

        if (strcmp(msg->getName(), "scan") == 0) {
            // Step 1: decide USING current accumulated values
            ThreatMode detected = decide();

            EV << "[Controller] t=" << simTime()
               << " rateSum=" << rateSum
               << " maxPayload=" << maxPayload
               << " maxLatency=" << maxLatency
               << " currentMode=" << modeName(currentMode)
               << " detected=" << modeName(detected) << "\n";

            // Step 2: switch and broadcast if changed
            if (detected != currentMode) {
                EV << "★★★ [Controller] GLOBAL MODE SWITCH: "
                   << modeName(currentMode) << " → "
                   << modeName(detected)
                   << " at t=" << simTime() << " ★★★\n";
                currentMode = detected;
                switchCount++;
                broadcast(detected);
                recordScalar("mode switch at", simTime().dbl());
                recordScalar("mode switched to", (int)detected);
            }

            // Step 3: reset AFTER deciding
            rateSum = 0; maxPayload = 0; maxLatency = 0;
            scheduleAt(simTime() + 1, msg);
            return;
        }
        delete msg;
    }

    ThreatMode decide() {
        // DDoS: high packet rate (most dangerous, check first)
        if (rateSum > DDOS_RATE_THRESH)          return MODE_DDOS;
        // SQLi: oversized payload (specific signature)
        if (maxPayload > SQLI_PAYLOAD_THRESH)     return MODE_SQLI;
        // MitM: abnormal latency (delayed/replayed packets)
        if (maxLatency > MITM_LATENCY_THRESH)     return MODE_MITM;
        // No attack detected
        return MODE_NORMAL;
    }

    void broadcast(ThreatMode m) {
        cModule *net = getSimulation()->getSystemModule();
        if (!net) {
            EV << "[Controller] ERROR: cannot get system module\n";
            return;
        }

        // Edge nodes
        for (int i = 0; i < 3; i++) {
            cModule *mod = net->getSubmodule("edge", i);
            if (mod) sendDirect(new ModeChangeMsg(m), mod, "controlIn");
            else EV << "[Controller] WARNING: edge[" << i << "] not found\n";
        }
        // MIST nodes
        for (int i = 0; i < 2; i++) {
            cModule *mod = net->getSubmodule("mist", i);
            if (mod) sendDirect(new ModeChangeMsg(m), mod, "controlIn");
            else EV << "[Controller] WARNING: mist[" << i << "] not found\n";
        }
        // Fog
        cModule *fog = net->getSubmodule("fog");
        if (fog) sendDirect(new ModeChangeMsg(m), fog, "controlIn");
        else EV << "[Controller] WARNING: fog not found\n";
        // Cloud
        cModule *cloud = net->getSubmodule("cloud");
        if (cloud) sendDirect(new ModeChangeMsg(m), cloud, "controlIn");
        else EV << "[Controller] WARNING: cloud not found\n";

        EV << "[Controller] Broadcast mode=" << modeName(m)
           << " to all layers\n";
    }

    virtual void finish() override {
        recordScalar("total mode switches", switchCount);
        recordScalar("final mode", (int)currentMode);
    }
};
Define_Module(CentralController);


// ═════════════════════════════════════════════════════════════
//  IoTNode
//  iot[0] → DDoS flood (t>=5)
//  iot[1] → SQLi large payload (t>=15)
//  iot[2] → MitM delayed replay (t>=25)
// ═════════════════════════════════════════════════════════════
class IoTNode : public cSimpleModule {
  private:
    int packetCount = 0;

  protected:
    virtual void initialize() override {
        scheduleAt(simTime() + 1, new cMessage("tick"));
    }

    virtual void handleMessage(cMessage *msg) override {
        // reply coming back
        if (strcmp(msg->getName(), "SensorData") == 0) {
            EV << "IoT[" << getIndex() << "] RTT="
               << (simTime() - msg->getTimestamp()) << "\n";
            delete msg;
            return;
        }


//        }
        packetCount++;
        sendPkt(64.0);
        scheduleAt(simTime() + 1, msg);

        // -------------------------------
        // EXCLUSIVE ATTACK WINDOWS
        // -------------------------------

        // iot[0]: DDoS ONLY between 5–15
        if (getIndex() == 0 && simTime() >= 5 && simTime() < 15) {
            for (int i = 0; i < 9; i++) sendPkt(64.0);
            EV << "ATTACKER[DDoS] at t=" << simTime() << "\n";
        }

        // iot[1]: SQLi ONLY between 15–25
        if (getIndex() == 1 && simTime() >= 15 && simTime() < 25) {
            sendPkt(1200.0);
            EV << "ATTACKER[SQLi] at t=" << simTime() << "\n";
        }

        // iot[2]: MitM ONLY after 25
        if (getIndex() == 2 && simTime() >= 25) {
            cMessage *fake = new cMessage("SensorData");
            fake->setTimestamp(simTime() - 0.5);
            fake->addPar("payloadSize") = 64.0;
            send(fake, "out");
            EV << "ATTACKER[MitM] at t=" << simTime() << "\n";
        }
    }

    void sendPkt(double payloadBytes) {
        cMessage *pkt = new cMessage("SensorData");
        pkt->setTimestamp(simTime());
        pkt->addPar("payloadSize") = payloadBytes;
        send(pkt, "out");
    }
};
Define_Module(IoTNode);


// ═════════════════════════════════════════════════════════════
//  IDSBase — shared IDS logic for all layers
//
//  KEY DESIGN:
//  Each layer checks ALL THREE attack signatures on EVERY packet
//  regardless of current mode. Mode only changes THRESHOLDS,
//  not which checks run. This ensures SQLi and MitM are never
//  missed because DDoS is happening simultaneously.
// ═════════════════════════════════════════════════════════════
class IDSBase : public cSimpleModule {
  protected:
    ThreatMode mode = MODE_NORMAL;

    // Stats
    int totalPkts    = 0;
    int droppedPkts  = 0;
    int acceptedPkts = 0;
    int ddosDrops    = 0;
    int sqliDrops    = 0;
    int mitmDrops    = 0;

    simtime_t lastLatency = 0;
    bool      hasPrior    = false;
    double    sumLatency  = 0;
    double    sumJitter   = 0;

    // Rate window
    int       wCount = 0;
    simtime_t wStart = 0;



    // Rate thresholds per mode (pkts/s per node)
    int rateThresh() {
        switch(mode) {
            case MODE_DDOS:   return 2;  // very tight during DDoS
            case MODE_SQLI:   return 6;  // loose during SQLi
            case MODE_MITM:   return 6;  // loose during MitM
            default:          return 5;  // normal baseline
        }
    }

    // Payload thresholds per mode (bytes)
    double payloadThresh() {
        switch(mode) {
            case MODE_SQLI:   return 200.0; // very tight during SQLi
            case MODE_DDOS:   return 9999;  // not checking payload in DDoS
            case MODE_MITM:   return 9999;  // not checking payload in MitM
            default:          return 500.0; // normal baseline
        }
    }

    // Latency thresholds per mode (seconds)
    double latencyThresh() {
        switch(mode) {
            case MODE_MITM:   return 0.10; // very tight during MitM
            case MODE_DDOS:   return 9999; // not checking latency in DDoS
            case MODE_SQLI:   return 9999; // not checking latency in SQLi
            default:          return 0.50; // normal baseline
        }
    }

    void applyMode(ModeChangeMsg *m) {
        ThreatMode prev = mode;
        mode = m->newMode;
        delete m;
        if (mode != prev)
            EV << "★ [" << getName() << "] MODE → "
               << modeName(mode) << " at t=" << simTime() << "\n";
    }

    // Returns true if packet was malicious and dropped
    bool inspect(cMessage *msg) {
        // Compute metrics
        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior
                            ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();
        totalPkts++;

        double payload = msg->hasPar("payloadSize")
                         ? msg->par("payloadSize").doubleValue() : 64.0;

        // Rate window
        if (simTime() - wStart >= 1.0) { wCount = 0; wStart = simTime(); }
        wCount++;

        // ── Check 1: Rate (DDoS signature) ──
        if (wCount > rateThresh()) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP DDoS rate=" << wCount
               << " thresh=" << rateThresh()
               << " t=" << simTime() << "\n";
            ddosDrops++; droppedPkts++;
            recordScalar((std::string(getName())+" DDOS drop").c_str(),
                         simTime().dbl());
            delete msg;
            return true;
        }

        // ── Check 2: Payload (SQLi signature) ──
        // Always run this check regardless of mode
        if (payload > payloadThresh()) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP SQLi payload=" << payload
               << " thresh=" << payloadThresh()
               << " t=" << simTime() << "\n";
            sqliDrops++; droppedPkts++;
            recordScalar((std::string(getName())+" SQLI drop").c_str(),
                         simTime().dbl());
            delete msg;
            return true;
        }

        // ── Check 3: Latency (MitM signature) ──
        // Always run this check regardless of mode
        if (latency.dbl() > latencyThresh()) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP MitM latency=" << latency
               << " thresh=" << latencyThresh()
               << " t=" << simTime() << "\n";
            mitmDrops++; droppedPkts++;
            recordScalar((std::string(getName())+" MITM drop").c_str(),
                         simTime().dbl());
            delete msg;
            return true;
        }

        acceptedPkts++;
        return false;
    }

    void writeStats(const char* prefix) {
        double simT = simTime().dbl();
        std::string p(prefix);
        recordScalar((p+" total packets").c_str(),    totalPkts);
        recordScalar((p+" dropped packets").c_str(),  droppedPkts);
        recordScalar((p+" accepted packets").c_str(), acceptedPkts);
        recordScalar((p+" DDoS drops").c_str(),       ddosDrops);
        recordScalar((p+" SQLi drops").c_str(),       sqliDrops);
        recordScalar((p+" MitM drops").c_str(),       mitmDrops);
        recordScalar((p+" drop rate").c_str(),
            totalPkts > 0 ? (double)droppedPkts / totalPkts : 0);
        recordScalar((p+" detection rate").c_str(),
            totalPkts > 0 ? (double)droppedPkts / totalPkts : 0);
        recordScalar((p+" avg latency").c_str(),
            totalPkts > 0 ? sumLatency / totalPkts : 0);
        recordScalar((p+" avg jitter").c_str(),
            totalPkts > 0 ? sumJitter / totalPkts : 0);
        recordScalar((p+" throughput pps").c_str(),
            simT > 0 ? totalPkts / simT : 0);
        recordScalar((p+" accepted throughput pps").c_str(),
            simT > 0 ? acceptedPkts / simT : 0);
    }
};


// ═════════════════════════════════════════════════════════════
//  EdgeNode — Layer 1 IDS
// ═════════════════════════════════════════════════════════════
class EdgeNode : public IDSBase {
  private:
    int fwdPkts   = 0;
    int localPkts = 0;

    // Snapshot for EdgeReport (captured at packet arrival)
    double snapRate    = 0;
    double snapPayload = 0;
    double snapLatency = 0;

  protected:
    virtual void initialize() override {
        scheduleAt(simTime() + 1, new cMessage("report"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }
        if (msg->arrivedOn("fromMIST")) {
            delete msg;
            return;
        }
        if (strcmp(msg->getName(), "report") == 0) {
            sendReport();
            scheduleAt(simTime() + 1, msg);
            return;
        }

        // Snapshot values BEFORE inspect() (which increments wCount)
        double payload = msg->hasPar("payloadSize")
                         ? msg->par("payloadSize").doubleValue() : 64.0;
        double lat = (simTime() - msg->getTimestamp()).dbl();

        // Update snapshot (keep max seen this window)
        if (payload > snapPayload) snapPayload = payload;
        if (lat > snapLatency)     snapLatency = lat;
        snapRate = (double)(wCount + 1); // approximate, inspect will update wCount

        if (inspect(msg)) return;

        if (intrand(2) == 0) {
            localPkts++;
            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
        } else {
            fwdPkts++;
            send(msg, "toMIST");
        }
    }

    void sendReport() {
        cModule *net  = getSimulation()->getSystemModule();
        cModule *ctrl = net ? net->getSubmodule("controller") : nullptr;
        if (!ctrl) {
            EV << "[Edge] WARNING: controller not found\n";
            return;
        }
        cMessage *rpt = new cMessage("EdgeReport");
        rpt->addPar("rate")    = snapRate;
        rpt->addPar("payload") = snapPayload;
        rpt->addPar("latency") = snapLatency;
        rpt->addPar("jitter")  = 0.0;
        sendDirect(rpt, ctrl, "dataIn");

        // Reset snapshots after reporting
        snapRate = 0; snapPayload = 0; snapLatency = 0;
    }

    virtual void finish() override {
        writeStats("Edge");
        recordScalar("Edge forwarded", fwdPkts);
        recordScalar("Edge local",     localPkts);
    }
};
Define_Module(EdgeNode);


// ═════════════════════════════════════════════════════════════
//  MISTNode — Layer 2 IDS
// ═════════════════════════════════════════════════════════════
class MISTNode : public IDSBase {
  private:
    int fwdPkts   = 0;
    int localPkts = 0;

  protected:
    virtual void initialize() override {}

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (inspect(msg)) return;

        if (intrand(2) == 0) {
            localPkts++;
            int g = msg->getArrivalGate()->getIndex();
            if (g < gateSize("toEdge")) send(msg, "toEdge", g);
            else delete msg;
        } else {
            fwdPkts++;
            send(msg, "toFog");
        }
    }

    virtual void finish() override {
        writeStats("MIST");
        recordScalar("MIST forwarded", fwdPkts);
        recordScalar("MIST local",     localPkts);
    }
};
Define_Module(MISTNode);


// ═════════════════════════════════════════════════════════════
//  FogNode — Layer 3 IDS
// ═════════════════════════════════════════════════════════════
class FogNode : public IDSBase {
  private:
    int fwdPkts = 0;

  protected:
    virtual void initialize() override {}

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (inspect(msg)) return;

        fwdPkts++;
        send(msg, "toCloud");
    }

    virtual void finish() override {
        writeStats("Fog");
        recordScalar("Fog forwarded", fwdPkts);
    }
};
Define_Module(FogNode);


// ═════════════════════════════════════════════════════════════
//  CloudNode — Layer 4 IDS + throughput anomaly detection
// ═════════════════════════════════════════════════════════════
class CloudNode : public IDSBase {
  private:
    double runAvg          = 0;
    int    throughputDrops = 0;
    const double T_MULT    = 1.5;
    const int    T_WARMUP  = 5;

  protected:
    virtual void initialize() override {}

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (inspect(msg)) return;

        // Throughput spike detection (extra Cloud-level rule)
        double cur = (simTime().dbl() > 0)
                     ? totalPkts / simTime().dbl() : 0;
        runAvg = (runAvg == 0) ? cur : 0.8*runAvg + 0.2*cur;

        if (acceptedPkts >= T_WARMUP && runAvg > 0
                && cur > T_MULT * runAvg) {
            EV << "[Cloud-IDS][" << modeName(mode)
               << "] DROP throughput spike cur=" << cur
               << " avg=" << runAvg
               << " t=" << simTime() << "\n";
            throughputDrops++; droppedPkts++;
            acceptedPkts--;
            delete msg;
            return;
        }

        EV << "[Cloud] ACCEPTED t=" << simTime()
           << " mode=" << modeName(mode) << "\n";
        delete msg;
    }

    virtual void finish() override {
        writeStats("Cloud");
        recordScalar("Cloud throughput drops", throughputDrops);
    }
};
Define_Module(CloudNode);
