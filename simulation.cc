#include <omnetpp.h>
#include <cmath>
using namespace omnetpp;

// ─────────────────────────────────────────────
//  Threat modes
// ─────────────────────────────────────────────
enum ThreatMode { MODE_DDOS = 0, MODE_MITM = 1, MODE_SQLI = 2 };

const char* modeName(ThreatMode m) {
    if (m == MODE_DDOS) return "DDOS";
    if (m == MODE_MITM) return "MITM";
    return "SQLI";
}

// ─────────────────────────────────────────────
//  ModeChange message
// ─────────────────────────────────────────────
class ModeChangeMsg : public cMessage {
  public:
    ThreatMode newMode;
    ModeChangeMsg(ThreatMode m) : cMessage("ModeChange"), newMode(m) {}
};

// ─────────────────────────────────────────────
//  Hardcoded thresholds per mode per layer
//  (no JSON loading — eliminates that failure point)
// ─────────────────────────────────────────────
struct LayerThresholds {
    int    rate_pps;
    double payload_bytes;
    double latency_s;
};

// DDOS thresholds: tight rate, loose payload
LayerThresholds DDOS_THRESH[4] = {
    {3, 9999, 9999},  // edge:  drop if >3 pkts/s
    {3, 9999, 9999},  // mist:  drop if >3 pkts/s
    {2, 9999, 9999},  // fog:   drop if >2 pkts/s
    {2, 9999, 9999},  // cloud: drop if >2 pkts/s
};

// SQLI thresholds: tight payload, loose rate
LayerThresholds SQLI_THRESH[4] = {
    {99, 300,  9999},  // edge:  drop if payload >300 bytes
    {99, 300,  9999},  // mist:  drop if payload >300 bytes
    {99, 300,  9999},  // fog:   drop if payload >300 bytes
    {99, 300,  9999},  // cloud: drop if payload >300 bytes
};

// MITM thresholds: tight latency
LayerThresholds MITM_THRESH[4] = {
    {99, 9999, 0.15},  // edge:  drop if latency >0.15s
    {99, 9999, 0.20},  // mist:  drop if latency >0.20s
    {99, 9999, 0.25},  // fog:   drop if latency >0.25s
    {99, 9999, 0.30},  // cloud: drop if latency >0.30s
};


// ═════════════════════════════════════════════
//  CentralController
// ═════════════════════════════════════════════
class CentralController : public cSimpleModule {
  private:
    ThreatMode currentMode = MODE_DDOS;
    int switchCount = 0;

    // Accumulated from EdgeReports each second
    double rateSum    = 0;
    double maxPayload = 0;
    double maxLatency = 0;
    int    numReports = 0;

    // Detection triggers
    const double DDOS_RATE_TRIGGER    = 5.0;   // sum across all edges > 5
    const double SQLI_PAYLOAD_TRIGGER = 300.0; // any edge sees payload > 300
    const double MITM_LATENCY_TRIGGER = 0.10;  // any edge sees latency > 0.1s

  protected:
    virtual void initialize() override {
        EV << "[Controller] Started. Mode=DDOS (default)\n";
        scheduleAt(simTime() + 1.5, new cMessage("scan"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "EdgeReport") == 0) {
            rateSum    += msg->par("rate").doubleValue();
            double p    = msg->par("payload").doubleValue();
            double l    = msg->par("latency").doubleValue();
            if (p > maxPayload) maxPayload = p;
            if (l > maxLatency) maxLatency = l;
            numReports++;
            delete msg;
            return;
        }

        if (strcmp(msg->getName(), "scan") == 0) {
            // Decide mode BEFORE resetting
            ThreatMode detected = decide();

            EV << "[Controller] scan t=" << simTime()
               << " rateSum=" << rateSum
               << " maxPayload=" << maxPayload
               << " maxLatency=" << maxLatency
               << " → " << modeName(detected) << "\n";

            if (detected != currentMode) {
                EV << "★★★ [Controller] MODE SWITCH: "
                   << modeName(currentMode) << " → "
                   << modeName(detected) << " at t=" << simTime() << "\n";
                currentMode = detected;
                switchCount++;
                broadcast(detected);
                recordScalar("mode switch at", simTime().dbl());
            }

            // Reset AFTER deciding
            rateSum = 0; maxPayload = 0; maxLatency = 0; numReports = 0;
            scheduleAt(simTime() + 1, msg);
            return;
        }
        delete msg;
    }

    ThreatMode decide() {
        // Priority: DDoS > SQLi > MitM
        if (rateSum > DDOS_RATE_TRIGGER)        return MODE_DDOS;
        if (maxPayload > SQLI_PAYLOAD_TRIGGER)   return MODE_SQLI;
        if (maxLatency > MITM_LATENCY_TRIGGER)   return MODE_MITM;
        return currentMode;
    }

    void broadcast(ThreatMode m) {
        // Use getSimulation()->getSystemModule() to get root
        cModule *net = getSimulation()->getSystemModule();
        if (!net) { EV << "[Controller] ERROR: no system module\n"; return; }

        // Build list of targets
        const char* names[] = {"edge","edge","edge","mist","mist","fog","cloud",nullptr};
        int indices[]        = {0,     1,     2,     0,     1,     -1,   -1,    -1};

        for (int i = 0; names[i]; i++) {
            cModule *mod = nullptr;
            if (indices[i] >= 0)
                mod = net->getSubmodule(names[i], indices[i]);
            else
                mod = net->getSubmodule(names[i]);

            if (mod) {
                sendDirect(new ModeChangeMsg(m), mod, "controlIn");
                EV << "[Controller] → sent " << modeName(m)
                   << " to " << names[i] << "\n";
            } else {
                EV << "[Controller] WARNING: " << names[i] << " not found\n";
            }
        }
    }

    virtual void finish() override {
        recordScalar("total mode switches", switchCount);
        recordScalar("final mode", (int)currentMode);
    }
};
Define_Module(CentralController);


// ═════════════════════════════════════════════
//  IoTNode
//  iot[0] → DDoS flood (t≥5)
//  iot[1] → SQLi large payload (t≥15)
//  iot[2] → MitM delayed packet (t≥25)
// ═════════════════════════════════════════════
class IoTNode : public cSimpleModule {
  private:
    int packetCount = 0;

  protected:
    virtual void initialize() override {
        scheduleAt(simTime() + 1, new cMessage("tick"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "SensorData") == 0) {
            EV << "IoT[" << getIndex() << "] RTT="
               << (simTime() - msg->getTimestamp()) << "\n";
            delete msg;
            return;
        }

        packetCount++;
        sendPkt(64.0);  // normal packet
        scheduleAt(simTime() + 1, msg);

        // iot[0] DDoS
        if (getIndex() == 0 && simTime() >= 5) {
            for (int i = 0; i < 9; i++) sendPkt(64.0);
            EV << "ATTACKER[DDoS] flood at t=" << simTime() << "\n";
        }

        // iot[1] SQLi
        if (getIndex() == 1 && simTime() >= 15) {
            sendPkt(1200.0);
            EV << "ATTACKER[SQLi] large-payload at t=" << simTime() << "\n";
        }

        // iot[2] MitM
        if (getIndex() == 2 && simTime() >= 25) {
            cMessage *delayed = new cMessage("SensorData");
            delayed->setTimestamp(simTime() - 0.5); // fake old timestamp
            delayed->addPar("payloadSize") = 64.0;
            send(delayed, "out");
            EV << "ATTACKER[MitM] delayed-replay at t=" << simTime() << "\n";
        }
    }

    void sendPkt(double payload) {
        cMessage *pkt = new cMessage("SensorData");
        pkt->setTimestamp(simTime());
        pkt->addPar("payloadSize") = payload;
        send(pkt, "out");
    }
};
Define_Module(IoTNode);


// ═════════════════════════════════════════════
//  IDSBase — shared logic
// ═════════════════════════════════════════════
class IDSBase : public cSimpleModule {
  protected:
    ThreatMode mode     = MODE_DDOS;
    int layerIdx        = 0; // 0=edge,1=mist,2=fog,3=cloud

    int totalPkts    = 0;
    int droppedPkts  = 0;
    int acceptedPkts = 0;
    int idsAlerts    = 0;

    simtime_t lastLatency = 0;
    bool      hasPrior    = false;
    double    sumLatency  = 0;
    double    sumJitter   = 0;

    // rate window
    int       wCount = 0;
    simtime_t wStart  = 0;

    void applyMode(ModeChangeMsg *m) {
        ThreatMode prev = mode;
        mode = m->newMode;
        delete m;
        if (mode != prev)
            EV << "★ [" << getName() << "] MODE → "
               << modeName(mode) << " at t=" << simTime() << "\n";
    }

    // Returns true and drops if packet should be dropped
    bool checkAndDrop(cMessage *msg) {
        // Get active thresholds
        LayerThresholds *T;
        if      (mode == MODE_DDOS) T = &DDOS_THRESH[layerIdx];
        else if (mode == MODE_SQLI) T = &SQLI_THRESH[layerIdx];
        else                        T = &MITM_THRESH[layerIdx];

        // Compute metrics
        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();
        totalPkts++;

        // Rate window
        if (simTime() - wStart >= 1.0) { wCount = 0; wStart = simTime(); }
        wCount++;

        double payload = msg->hasPar("payloadSize") ?
                         msg->par("payloadSize").doubleValue() : 64.0;

        // Rate check
        if (wCount > T->rate_pps) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP rate=" << wCount << ">" << T->rate_pps
               << " t=" << simTime() << "\n";
            idsAlerts++; droppedPkts++;
            recordScalar((std::string(getName())+" drop").c_str(), simTime().dbl());
            delete msg;
            return true;
        }

        // Payload check
        if (payload > T->payload_bytes) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP payload=" << payload << ">" << T->payload_bytes
               << " t=" << simTime() << "\n";
            idsAlerts++; droppedPkts++;
            recordScalar((std::string(getName())+" drop").c_str(), simTime().dbl());
            delete msg;
            return true;
        }

        // Latency check
        if (latency.dbl() > T->latency_s) {
            EV << "[" << getName() << "-IDS][" << modeName(mode)
               << "] DROP latency=" << latency << ">" << T->latency_s
               << " t=" << simTime() << "\n";
            idsAlerts++; droppedPkts++;
            recordScalar((std::string(getName())+" drop").c_str(), simTime().dbl());
            delete msg;
            return true;
        }

        acceptedPkts++;
        return false;
    }

    void writeFinish(const char* prefix) {
        double simT = simTime().dbl();
        std::string p(prefix);
        recordScalar((p+" total packets").c_str(),    totalPkts);
        recordScalar((p+" dropped packets").c_str(),  droppedPkts);
        recordScalar((p+" accepted packets").c_str(), acceptedPkts);
        recordScalar((p+" IDS alerts").c_str(),       idsAlerts);
        recordScalar((p+" drop rate").c_str(),
            totalPkts>0 ? (double)droppedPkts/totalPkts : 0);
        recordScalar((p+" detection rate").c_str(),
            totalPkts>0 ? (double)idsAlerts/totalPkts : 0);
        recordScalar((p+" avg latency").c_str(),
            totalPkts>0 ? sumLatency/totalPkts : 0);
        recordScalar((p+" throughput").c_str(),
            simT>0 ? totalPkts/simT : 0);
    }
};


// ═════════════════════════════════════════════
//  EdgeNode
// ═════════════════════════════════════════════
class EdgeNode : public IDSBase {
  private:
    int fwdPkts   = 0;
    int localPkts = 0;

    // snapshot for reporting
    double snapRate    = 0;
    double snapPayload = 0;
    double snapLatency = 0;

  protected:
    virtual void initialize() override {
        layerIdx = 0;
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

        // Snapshot BEFORE checkAndDrop (which may delete msg)
        snapRate    = (double)(wCount + 1); // +1 because wCount not yet incremented
        if (msg->hasPar("payloadSize"))
            snapPayload = msg->par("payloadSize").doubleValue();
        snapLatency = (simTime() - msg->getTimestamp()).dbl();

        if (checkAndDrop(msg)) return;

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
        if (!ctrl) return;

        cMessage *rpt = new cMessage("EdgeReport");
        rpt->addPar("rate")    = snapRate;
        rpt->addPar("payload") = snapPayload;
        rpt->addPar("latency") = snapLatency;
        rpt->addPar("jitter")  = 0.0;
        sendDirect(rpt, ctrl, "dataIn");
    }

    virtual void finish() override {
        writeFinish("Edge");
        recordScalar("Edge forwarded", fwdPkts);
        recordScalar("Edge local",     localPkts);
    }
};
Define_Module(EdgeNode);


// ═════════════════════════════════════════════
//  MISTNode
// ═════════════════════════════════════════════
class MISTNode : public IDSBase {
  private:
    int fwdPkts   = 0;
    int localPkts = 0;

  protected:
    virtual void initialize() override { layerIdx = 1; }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (checkAndDrop(msg)) return;

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
        writeFinish("MIST");
        recordScalar("MIST forwarded", fwdPkts);
        recordScalar("MIST local",     localPkts);
    }
};
Define_Module(MISTNode);


// ═════════════════════════════════════════════
//  FogNode
// ═════════════════════════════════════════════
class FogNode : public IDSBase {
  private:
    int fwdPkts = 0;

  protected:
    virtual void initialize() override { layerIdx = 2; }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (checkAndDrop(msg)) return;

        fwdPkts++;
        send(msg, "toCloud");
    }

    virtual void finish() override {
        writeFinish("Fog");
        recordScalar("Fog forwarded", fwdPkts);
    }
};
Define_Module(FogNode);


// ═════════════════════════════════════════════
//  CloudNode
// ═════════════════════════════════════════════
class CloudNode : public IDSBase {
  private:
    double runAvg           = 0;
    int    throughputDrops  = 0;
    const double T_MULT     = 1.5;
    const int    T_WARMUP   = 5;

  protected:
    virtual void initialize() override { layerIdx = 3; }

    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("controlIn")) {
            applyMode((ModeChangeMsg*)msg);
            return;
        }

        if (checkAndDrop(msg)) return;

        double cur = totalPkts / simTime().dbl();
        runAvg = (runAvg == 0) ? cur : 0.8*runAvg + 0.2*cur;

        if (acceptedPkts >= T_WARMUP && runAvg > 0
                && cur > T_MULT * runAvg) {
            throughputDrops++; idsAlerts++; droppedPkts++;
            acceptedPkts--;  // undo the increment from checkAndDrop
            EV << "[Cloud-IDS][" << modeName(mode)
               << "] DROP throughput spike t=" << simTime() << "\n";
            delete msg;
            return;
        }

        EV << "[Cloud] ACCEPTED latency="
           << (simTime() - SIMTIME_ZERO) << " t=" << simTime() << "\n";
        delete msg;
    }

    virtual void finish() override {
        writeFinish("Cloud");
        recordScalar("Cloud throughput drops", throughputDrops);
    }
};
Define_Module(CloudNode);
