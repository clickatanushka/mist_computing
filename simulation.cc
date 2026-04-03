#include <omnetpp.h>
#include <cmath>
using namespace omnetpp;

// ============================================================
//  IoT Node — sensor device, iot[0] is the rogue attacker
// ============================================================
class IoTNode : public cSimpleModule {
  private:
    int packetCount  = 0;
    int attackPackets = 0;
    bool isRogue     = false;

  protected:
    virtual void initialize() override {
        isRogue = (getIndex() == 0);
        scheduleAt(simTime() + 1, new cMessage("timer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "SensorData") == 0) {
            // reply received back from Edge
            simtime_t responseTime = simTime() - msg->getTimestamp();
            EV << "IoT[" << getIndex() << "] got reply! RTT=" << responseTime << "\n";
            delete msg;
            return;
        }
        // timer fired — send normal packet
        packetCount++;
        cMessage *pkt = new cMessage("SensorData");
        pkt->setTimestamp(simTime());
        send(pkt, "out");
        EV << "IoT[" << getIndex() << "] sent packet #" << packetCount << " at t=" << simTime() << "\n";
        scheduleAt(simTime() + 1, msg);

        // rogue flood after t=5
        if (isRogue && simTime() >= 5) {
            attackPackets++;
            for (int i = 0; i < 9; i++) {
                cMessage *atk = new cMessage("SensorData");
                atk->setTimestamp(simTime());
                send(atk, "out");
            }
            EV << "ATTACKER flood #" << attackPackets << " at t=" << simTime() << "\n";
        }
    }
};
Define_Module(IoTNode);

// ============================================================
//  Edge Node — Layer 1 IDS
//  Rule: Rate-based only (packet count per 1s window)
//  Threshold: > 5 packets/s → alert & drop
// ============================================================
class EdgeNode : public cSimpleModule {
  private:
    // traffic stats
    int totalPackets  = 0;
    int droppedPackets = 0;
    int forwardedPackets = 0;
    int localPackets  = 0;
    simtime_t lastLatency = 0;
    double sumLatency = 0;
    double sumJitter  = 0;

    // IDS — rate window
    int windowCount   = 0;
    simtime_t windowStart = 0;

    // IDS counters
    int idsAlerts     = 0;
    int idsDropped    = 0;

    // thresholds
    const int RATE_THRESHOLD = 5;   // packets per second

  protected:
    virtual void handleMessage(cMessage *msg) override {

        // reply arriving from MIST — relay back to IoT
        if (msg->arrivedOn("fromMIST")) {
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toIoT", gateIndex);
            return;
        }

        totalPackets++;

        // --- IDS Layer 1: Rate-based check ---
        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        if (windowCount > RATE_THRESHOLD) {
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[EDGE-IDS] ALERT: Rate=" << windowCount
               << "/s exceeds threshold=" << RATE_THRESHOLD
               << " — packet DROPPED at t=" << simTime() << "\n";
            recordScalar("Edge IDS alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- normal processing ---
        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        EV << "[Edge] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter << "\n";

        if (intrand(2) == 0) {
            localPackets++;
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toIoT", gateIndex);
            EV << "[Edge] handled LOCALLY\n";
        } else {
            forwardedPackets++;
            send(msg, "toMIST");
            EV << "[Edge] forwarded to MIST\n";
        }
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        EV << "\n=== EDGE IDS COMPARATIVE REPORT ===\n";
        recordScalar("Edge total packets",       totalPackets);
        recordScalar("Edge dropped packets",     droppedPackets);
        recordScalar("Edge forwarded packets",   forwardedPackets);
        recordScalar("Edge local packets",       localPackets);
        recordScalar("Edge IDS alerts",          idsAlerts);
        recordScalar("Edge IDS dropped",         idsDropped);
        recordScalar("Edge avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
        recordScalar("Edge avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
        recordScalar("Edge throughput",          totalPackets / simT);
        recordScalar("Edge drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
        recordScalar("Edge detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
    }
};
Define_Module(EdgeNode);

// ============================================================
//  MIST Node — Layer 2 IDS
//  Rule 1: Rate-based  (> 4 packets/s)
//  Rule 2: Jitter threshold (jitter > 0.05s)
// ============================================================
class MISTNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int forwardedPackets = 0;
    int localPackets     = 0;
    simtime_t lastLatency = 0;
    double sumLatency    = 0;
    double sumJitter     = 0;

    // IDS — rate window
    int windowCount      = 0;
    simtime_t windowStart = 0;

    // IDS counters
    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;

    // thresholds
    const int    RATE_THRESHOLD   = 4;     // stricter than Edge
    const double JITTER_THRESHOLD = 0.05;  // seconds

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        // --- IDS Layer 2, Rule 1: Rate check ---
        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        if (windowCount > RATE_THRESHOLD) {
            rateAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[MIST-IDS] ALERT R1: Rate=" << windowCount
               << "/s > threshold=" << RATE_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("MIST IDS rate alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 2, Rule 2: Jitter check ---
        if (jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[MIST-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("MIST IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- normal processing ---
        EV << "[MIST] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter << "\n";

        if (intrand(2) == 0) {
            localPackets++;
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toEdge", gateIndex);
            EV << "[MIST] handled LOCALLY\n";
        } else {
            forwardedPackets++;
            send(msg, "toFog");
            EV << "[MIST] forwarded to FOG\n";
        }
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        EV << "\n=== MIST IDS COMPARATIVE REPORT ===\n";
        recordScalar("MIST total packets",       totalPackets);
        recordScalar("MIST dropped packets",     droppedPackets);
        recordScalar("MIST forwarded packets",   forwardedPackets);
        recordScalar("MIST local packets",       localPackets);
        recordScalar("MIST IDS alerts",          idsAlerts);
        recordScalar("MIST IDS dropped",         idsDropped);
        recordScalar("MIST IDS rate alerts",     rateAlerts);
        recordScalar("MIST IDS jitter alerts",   jitterAlerts);
        recordScalar("MIST avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
        recordScalar("MIST avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
        recordScalar("MIST throughput",          totalPackets / simT);
        recordScalar("MIST drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
        recordScalar("MIST detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
    }
};
Define_Module(MISTNode);

// ============================================================
//  Fog Node — Layer 3 IDS
//  Rule 1: Rate-based  (> 3 packets/s)
//  Rule 2: Jitter threshold (> 0.03s)
//  Rule 3: Latency threshold (> 0.3s)
// ============================================================
class FogNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int forwardedPackets = 0;
    simtime_t lastLatency = 0;
    double sumLatency    = 0;
    double sumJitter     = 0;

    // IDS — rate window
    int windowCount      = 0;
    simtime_t windowStart = 0;

    // IDS counters
    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;
    int latencyAlerts    = 0;

    // thresholds
    const int    RATE_THRESHOLD    = 3;
    const double JITTER_THRESHOLD  = 0.03;
    const double LATENCY_THRESHOLD = 0.3;   // seconds

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        // --- IDS Layer 3, Rule 1: Rate check ---
        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        if (windowCount > RATE_THRESHOLD) {
            rateAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[FOG-IDS] ALERT R1: Rate=" << windowCount
               << "/s > threshold=" << RATE_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Fog IDS rate alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 3, Rule 2: Jitter check ---
        if (jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[FOG-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Fog IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 3, Rule 3: Latency check ---
        if (latency.dbl() > LATENCY_THRESHOLD) {
            latencyAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[FOG-IDS] ALERT R3: Latency=" << latency
               << "s > threshold=" << LATENCY_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Fog IDS latency alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- normal processing — forward to Cloud ---
        forwardedPackets++;
        EV << "[Fog] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter
           << " — forwarded to Cloud\n";
        send(msg, "toCloud");
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        EV << "\n=== FOG IDS COMPARATIVE REPORT ===\n";
        recordScalar("Fog total packets",        totalPackets);
        recordScalar("Fog dropped packets",      droppedPackets);
        recordScalar("Fog forwarded packets",    forwardedPackets);
        recordScalar("Fog IDS alerts",           idsAlerts);
        recordScalar("Fog IDS dropped",          idsDropped);
        recordScalar("Fog IDS rate alerts",      rateAlerts);
        recordScalar("Fog IDS jitter alerts",    jitterAlerts);
        recordScalar("Fog IDS latency alerts",   latencyAlerts);
        recordScalar("Fog avg latency",          totalPackets > 0 ? sumLatency / totalPackets : 0);
        recordScalar("Fog avg jitter",           totalPackets > 0 ? sumJitter  / totalPackets : 0);
        recordScalar("Fog throughput",           totalPackets / simT);
        recordScalar("Fog drop rate",            totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
        recordScalar("Fog detection rate",       totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
    }
};
Define_Module(FogNode);

// ============================================================
//  Cloud Node — Layer 4 IDS (most comprehensive)
//  Rule 1: Rate-based         (> 2 packets/s)
//  Rule 2: Jitter threshold   (> 0.02s)
//  Rule 3: Latency threshold  (> 0.5s)
//  Rule 4: Throughput anomaly (throughput > 1.5x running average)
// ============================================================
class CloudNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int acceptedPackets  = 0;
    simtime_t lastLatency = 0;
    double sumLatency    = 0;
    double sumJitter     = 0;

    // IDS — rate window
    int windowCount      = 0;
    simtime_t windowStart = 0;

    // throughput anomaly tracking
    double runningAvgThroughput = 0;

    // IDS counters
    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;
    int latencyAlerts    = 0;
    int throughputAlerts = 0;

    // thresholds
    const int    RATE_THRESHOLD        = 2;
    const double JITTER_THRESHOLD      = 0.02;
    const double LATENCY_THRESHOLD     = 0.5;
    const double THROUGHPUT_MULTIPLIER = 1.5;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        double currentThroughput = totalPackets / simTime().dbl();
        // update running average (exponential moving average)
        if (runningAvgThroughput == 0)
            runningAvgThroughput = currentThroughput;
        else
            runningAvgThroughput = 0.8 * runningAvgThroughput + 0.2 * currentThroughput;

        // --- IDS Layer 4, Rule 1: Rate check ---
        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        if (windowCount > RATE_THRESHOLD) {
            rateAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R1: Rate=" << windowCount
               << "/s > threshold=" << RATE_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS rate alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 4, Rule 2: Jitter check ---
        if (jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 4, Rule 3: Latency check ---
        if (latency.dbl() > LATENCY_THRESHOLD) {
            latencyAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R3: Latency=" << latency
               << "s > threshold=" << LATENCY_THRESHOLD
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS latency alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- IDS Layer 4, Rule 4: Throughput anomaly check ---
        if (runningAvgThroughput > 0 &&
            currentThroughput > THROUGHPUT_MULTIPLIER * runningAvgThroughput) {
            throughputAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R4: Throughput=" << currentThroughput
               << " > " << THROUGHPUT_MULTIPLIER << "x avg=" << runningAvgThroughput
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS throughput alert at", simTime().dbl());
            delete msg;
            return;
        }

        // --- packet accepted ---
        acceptedPackets++;
        EV << "[Cloud] pkt #" << totalPackets
           << " ACCEPTED | latency=" << latency
           << " jitter=" << jitter
           << " throughput=" << currentThroughput << "\n";
        delete msg;
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        EV << "\n=== CLOUD IDS COMPARATIVE REPORT ===\n";
        recordScalar("Cloud total packets",          totalPackets);
        recordScalar("Cloud accepted packets",       acceptedPackets);
        recordScalar("Cloud dropped packets",        droppedPackets);
        recordScalar("Cloud IDS alerts",             idsAlerts);
        recordScalar("Cloud IDS dropped",            idsDropped);
        recordScalar("Cloud IDS rate alerts",        rateAlerts);
        recordScalar("Cloud IDS jitter alerts",      jitterAlerts);
        recordScalar("Cloud IDS latency alerts",     latencyAlerts);
        recordScalar("Cloud IDS throughput alerts",  throughputAlerts);
        recordScalar("Cloud avg latency",            totalPackets > 0 ? sumLatency / totalPackets : 0);
        recordScalar("Cloud avg jitter",             totalPackets > 0 ? sumJitter  / totalPackets : 0);
        recordScalar("Cloud throughput",             totalPackets / simT);
        recordScalar("Cloud drop rate",              totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
        recordScalar("Cloud detection rate",         totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
    }
};
Define_Module(CloudNode);
