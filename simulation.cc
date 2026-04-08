//#include <omnetpp.h>
//#include <cmath>
//using namespace omnetpp;
//
//// ============================================================
////  IoT Node — sensor device, iot[0] is the rogue attacker
//// ============================================================
//class IoTNode : public cSimpleModule {
//  private:
//    int packetCount  = 0;
//    int attackPackets = 0;
//    bool isRogue     = false;
//
//  protected:
//    virtual void initialize() override {
//        isRogue = (getIndex() == 0);
//        scheduleAt(simTime() + 1, new cMessage("timer"));
//    }
//
//    virtual void handleMessage(cMessage *msg) override {
//        if (strcmp(msg->getName(), "SensorData") == 0) {
//            // reply received back from Edge
//            simtime_t responseTime = simTime() - msg->getTimestamp();
//            EV << "IoT[" << getIndex() << "] got reply! RTT=" << responseTime << "\n";
//            delete msg;
//            return;
//        }
//        // timer fired — send normal packet
//        packetCount++;
//        cMessage *pkt = new cMessage("SensorData");
//        pkt->setTimestamp(simTime());
//        send(pkt, "out");
//        EV << "IoT[" << getIndex() << "] sent packet #" << packetCount << " at t=" << simTime() << "\n";
//        scheduleAt(simTime() + 1, msg);
//
//        // rogue flood after t=5
//        if (isRogue && simTime() >= 5) {
//            attackPackets++;
//            for (int i = 0; i < 9; i++) {
//                cMessage *atk = new cMessage("SensorData");
//                atk->setTimestamp(simTime());
//                send(atk, "out");
//            }
//            EV << "ATTACKER flood #" << attackPackets << " at t=" << simTime() << "\n";
//        }
//    }
//};
//Define_Module(IoTNode);
//
//// ============================================================
////  Edge Node — Layer 1 IDS
////  Rule: Rate-based only (packet count per 1s window)
////  Threshold: > 5 packets/s → alert & drop
//// ============================================================
//class EdgeNode : public cSimpleModule {
//  private:
//    // traffic stats
//    int totalPackets  = 0;
//    int droppedPackets = 0;
//    int forwardedPackets = 0;
//    int localPackets  = 0;
//    simtime_t lastLatency = 0;
//    double sumLatency = 0;
//    double sumJitter  = 0;
//
//    // IDS — rate window
//    int windowCount   = 0;
//    simtime_t windowStart = 0;
//
//    // IDS counters
//    int idsAlerts     = 0;
//    int idsDropped    = 0;
//
//    // thresholds
//    const int RATE_THRESHOLD = 5;   // packets per second
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//
//        // reply arriving from MIST — relay back to IoT
//        if (msg->arrivedOn("fromMIST")) {
//            int gateIndex = msg->getArrivalGate()->getIndex();
//            send(msg, "toIoT", gateIndex);
//            return;
//        }
//
//        totalPackets++;
//
//        // --- IDS Layer 1: Rate-based check ---
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        if (windowCount > RATE_THRESHOLD) {
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[EDGE-IDS] ALERT: Rate=" << windowCount
//               << "/s exceeds threshold=" << RATE_THRESHOLD
//               << " — packet DROPPED at t=" << simTime() << "\n";
//            recordScalar("Edge IDS alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- normal processing ---
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = fabs((latency - lastLatency).dbl());
//        lastLatency = latency;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        EV << "[Edge] pkt #" << totalPackets
//           << " latency=" << latency << " jitter=" << jitter << "\n";
//
//        if (intrand(2) == 0) {
//            localPackets++;
//            int gateIndex = msg->getArrivalGate()->getIndex();
//            send(msg, "toIoT", gateIndex);
//            EV << "[Edge] handled LOCALLY\n";
//        } else {
//            forwardedPackets++;
//            send(msg, "toMIST");
//            EV << "[Edge] forwarded to MIST\n";
//        }
//    }
//
//    virtual void finish() override {
//        double simT = simTime().dbl();
//        EV << "\n=== EDGE IDS COMPARATIVE REPORT ===\n";
//        recordScalar("Edge total packets",       totalPackets);
//        recordScalar("Edge dropped packets",     droppedPackets);
//        recordScalar("Edge forwarded packets",   forwardedPackets);
//        recordScalar("Edge local packets",       localPackets);
//        recordScalar("Edge IDS alerts",          idsAlerts);
//        recordScalar("Edge IDS dropped",         idsDropped);
//        recordScalar("Edge avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
//        recordScalar("Edge avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
//        recordScalar("Edge throughput",          totalPackets / simT);
//        recordScalar("Edge drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
//        recordScalar("Edge detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
//    }
//};
//Define_Module(EdgeNode);
//
//// ============================================================
////  MIST Node — Layer 2 IDS
////  Rule 1: Rate-based  (> 4 packets/s)
////  Rule 2: Jitter threshold (jitter > 0.05s)
//// ============================================================
//class MISTNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int forwardedPackets = 0;
//    int localPackets     = 0;
//    simtime_t lastLatency = 0;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    // IDS — rate window
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//
//    // IDS counters
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//
//    // thresholds
//    const int    RATE_THRESHOLD   = 4;     // stricter than Edge
//    const double JITTER_THRESHOLD = 0.05;  // seconds
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = fabs((latency - lastLatency).dbl());
//        lastLatency = latency;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        // --- IDS Layer 2, Rule 1: Rate check ---
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        if (windowCount > RATE_THRESHOLD) {
//            rateAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[MIST-IDS] ALERT R1: Rate=" << windowCount
//               << "/s > threshold=" << RATE_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("MIST IDS rate alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 2, Rule 2: Jitter check ---
//        if (jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[MIST-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("MIST IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- normal processing ---
//        EV << "[MIST] pkt #" << totalPackets
//           << " latency=" << latency << " jitter=" << jitter << "\n";
//
//        if (intrand(2) == 0) {
//            localPackets++;
//            int gateIndex = msg->getArrivalGate()->getIndex();
//            send(msg, "toEdge", gateIndex);
//            EV << "[MIST] handled LOCALLY\n";
//        } else {
//            forwardedPackets++;
//            send(msg, "toFog");
//            EV << "[MIST] forwarded to FOG\n";
//        }
//    }
//
//    virtual void finish() override {
//        double simT = simTime().dbl();
//        EV << "\n=== MIST IDS COMPARATIVE REPORT ===\n";
//        recordScalar("MIST total packets",       totalPackets);
//        recordScalar("MIST dropped packets",     droppedPackets);
//        recordScalar("MIST forwarded packets",   forwardedPackets);
//        recordScalar("MIST local packets",       localPackets);
//        recordScalar("MIST IDS alerts",          idsAlerts);
//        recordScalar("MIST IDS dropped",         idsDropped);
//        recordScalar("MIST IDS rate alerts",     rateAlerts);
//        recordScalar("MIST IDS jitter alerts",   jitterAlerts);
//        recordScalar("MIST avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
//        recordScalar("MIST avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
//        recordScalar("MIST throughput",          totalPackets / simT);
//        recordScalar("MIST drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
//        recordScalar("MIST detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
//    }
//};
//Define_Module(MISTNode);
//
//// ============================================================
////  Fog Node — Layer 3 IDS
////  Rule 1: Rate-based  (> 3 packets/s)
////  Rule 2: Jitter threshold (> 0.03s)
////  Rule 3: Latency threshold (> 0.3s)
//// ============================================================
//class FogNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int forwardedPackets = 0;
//    simtime_t lastLatency = 0;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    // IDS — rate window
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//
//    // IDS counters
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//    int latencyAlerts    = 0;
//
//    // thresholds
//    const int    RATE_THRESHOLD    = 3;
//    const double JITTER_THRESHOLD  = 0.03;
//    const double LATENCY_THRESHOLD = 0.3;   // seconds
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = fabs((latency - lastLatency).dbl());
//        lastLatency = latency;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        // --- IDS Layer 3, Rule 1: Rate check ---
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        if (windowCount > RATE_THRESHOLD) {
//            rateAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[FOG-IDS] ALERT R1: Rate=" << windowCount
//               << "/s > threshold=" << RATE_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Fog IDS rate alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 3, Rule 2: Jitter check ---
//        if (jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[FOG-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Fog IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 3, Rule 3: Latency check ---
//        if (latency.dbl() > LATENCY_THRESHOLD) {
//            latencyAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[FOG-IDS] ALERT R3: Latency=" << latency
//               << "s > threshold=" << LATENCY_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Fog IDS latency alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- normal processing — forward to Cloud ---
//        forwardedPackets++;
//        EV << "[Fog] pkt #" << totalPackets
//           << " latency=" << latency << " jitter=" << jitter
//           << " — forwarded to Cloud\n";
//        send(msg, "toCloud");
//    }
//
//    virtual void finish() override {
//        double simT = simTime().dbl();
//        EV << "\n=== FOG IDS COMPARATIVE REPORT ===\n";
//        recordScalar("Fog total packets",        totalPackets);
//        recordScalar("Fog dropped packets",      droppedPackets);
//        recordScalar("Fog forwarded packets",    forwardedPackets);
//        recordScalar("Fog IDS alerts",           idsAlerts);
//        recordScalar("Fog IDS dropped",          idsDropped);
//        recordScalar("Fog IDS rate alerts",      rateAlerts);
//        recordScalar("Fog IDS jitter alerts",    jitterAlerts);
//        recordScalar("Fog IDS latency alerts",   latencyAlerts);
//        recordScalar("Fog avg latency",          totalPackets > 0 ? sumLatency / totalPackets : 0);
//        recordScalar("Fog avg jitter",           totalPackets > 0 ? sumJitter  / totalPackets : 0);
//        recordScalar("Fog throughput",           totalPackets / simT);
//        recordScalar("Fog drop rate",            totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
//        recordScalar("Fog detection rate",       totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
//    }
//};
//Define_Module(FogNode);
//
//// ============================================================
////  Cloud Node — Layer 4 IDS (most comprehensive)
////  Rule 1: Rate-based         (> 2 packets/s)
////  Rule 2: Jitter threshold   (> 0.02s)
////  Rule 3: Latency threshold  (> 0.5s)
////  Rule 4: Throughput anomaly (throughput > 1.5x running average)
//// ============================================================
//class CloudNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int acceptedPackets  = 0;
//    simtime_t lastLatency = 0;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    // IDS — rate window
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//
//    // throughput anomaly tracking
//    double runningAvgThroughput = 0;
//
//    // IDS counters
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//    int latencyAlerts    = 0;
//    int throughputAlerts = 0;
//
//    // thresholds
//    const int    RATE_THRESHOLD        = 2;
//    const double JITTER_THRESHOLD      = 0.02;
//    const double LATENCY_THRESHOLD     = 0.5;
//    const double THROUGHPUT_MULTIPLIER = 1.5;
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = fabs((latency - lastLatency).dbl());
//        lastLatency = latency;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        double currentThroughput = totalPackets / simTime().dbl();
//        // update running average (exponential moving average)
//        if (runningAvgThroughput == 0)
//            runningAvgThroughput = currentThroughput;
//        else
//            runningAvgThroughput = 0.8 * runningAvgThroughput + 0.2 * currentThroughput;
//
//        // --- IDS Layer 4, Rule 1: Rate check ---
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        if (windowCount > RATE_THRESHOLD) {
//            rateAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R1: Rate=" << windowCount
//               << "/s > threshold=" << RATE_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS rate alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 4, Rule 2: Jitter check ---
//        if (jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 4, Rule 3: Latency check ---
//        if (latency.dbl() > LATENCY_THRESHOLD) {
//            latencyAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R3: Latency=" << latency
//               << "s > threshold=" << LATENCY_THRESHOLD
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS latency alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- IDS Layer 4, Rule 4: Throughput anomaly check ---
//        if (runningAvgThroughput > 0 &&
//            currentThroughput > THROUGHPUT_MULTIPLIER * runningAvgThroughput) {
//            throughputAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R4: Throughput=" << currentThroughput
//               << " > " << THROUGHPUT_MULTIPLIER << "x avg=" << runningAvgThroughput
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS throughput alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // --- packet accepted ---
//        acceptedPackets++;
//        EV << "[Cloud] pkt #" << totalPackets
//           << " ACCEPTED | latency=" << latency
//           << " jitter=" << jitter
//           << " throughput=" << currentThroughput << "\n";
//        delete msg;
//    }
//
//    virtual void finish() override {
//        double simT = simTime().dbl();
//        EV << "\n=== CLOUD IDS COMPARATIVE REPORT ===\n";
//        recordScalar("Cloud total packets",          totalPackets);
//        recordScalar("Cloud accepted packets",       acceptedPackets);
//        recordScalar("Cloud dropped packets",        droppedPackets);
//        recordScalar("Cloud IDS alerts",             idsAlerts);
//        recordScalar("Cloud IDS dropped",            idsDropped);
//        recordScalar("Cloud IDS rate alerts",        rateAlerts);
//        recordScalar("Cloud IDS jitter alerts",      jitterAlerts);
//        recordScalar("Cloud IDS latency alerts",     latencyAlerts);
//        recordScalar("Cloud IDS throughput alerts",  throughputAlerts);
//        recordScalar("Cloud avg latency",            totalPackets > 0 ? sumLatency / totalPackets : 0);
//        recordScalar("Cloud avg jitter",             totalPackets > 0 ? sumJitter  / totalPackets : 0);
//        recordScalar("Cloud throughput",             totalPackets / simT);
//        recordScalar("Cloud drop rate",              totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
//        recordScalar("Cloud detection rate",         totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
//    }
//};
//Define_Module(CloudNode);


#include <omnetpp.h>
#include <cmath>
using namespace omnetpp;

// ============================================================
//  IoTNode — sensor device
//  iot[0] doubles as the rogue attacker after t=5s
//  No changes needed from original.
// ============================================================
class IoTNode : public cSimpleModule {
  private:
    int packetCount   = 0;
    int attackPackets = 0;
    bool isRogue      = false;

  protected:
    virtual void initialize() override {
        isRogue = (getIndex() == 0);
        scheduleAt(simTime() + 1, new cMessage("timer"));
    }

    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "SensorData") == 0) {
            simtime_t rtt = simTime() - msg->getTimestamp();
            EV << "IoT[" << getIndex() << "] got reply! RTT=" << rtt << "\n";
            delete msg;
            return;
        }
        packetCount++;
        cMessage *pkt = new cMessage("SensorData");
        pkt->setTimestamp(simTime());
        send(pkt, "out");
//
//        cMessage *pkt = new cMessage("SensorData");
//        pkt->setTimestamp(simTime());// ADD THESE 👇
//        pkt->addPar("srcId") = getIndex();
//        pkt->addPar("isAttack") = false;
        send(pkt, "out");
        EV << "IoT[" << getIndex() << "] sent packet #" << packetCount
           << " at t=" << simTime() << "\n";
        scheduleAt(simTime() + 1, msg);

        if (isRogue && simTime() >= 5) {
            attackPackets++;
            for (int i = 0; i < 9; i++) {
                cMessage *atk = new cMessage("SensorData");
                atk->setTimestamp(simTime());
                send(atk, "out");
//                cMessage *atk = new cMessage("SensorData");
//                atk->setTimestamp(simTime());
//
//                // ADD THESE 👇
//                atk->addPar("srcId") = getIndex();
//                atk->addPar("isAttack") = true;
//
//                send(atk, "out");
            }
            EV << "ATTACKER flood #" << attackPackets
               << " at t=" << simTime() << "\n";
        }
    }
};
Define_Module(IoTNode);

// ============================================================
//  EdgeNode — Layer 1 IDS
//
//  RULE: Rate > 5 pkt/s → DROP
//
//  WHY no jitter check here:
//    Edge sees raw IoT traffic arriving at exactly 5ms latency
//    every time (fixed channel delay, no queuing in this model).
//    Jitter is always 0 for legitimate single-source packets.
//    Adding a jitter check here would only add complexity with
//    no detection benefit.
//
//  FIX applied: hasPrior cold-start guard (prevents jitter=0.005
//    on packet #1 being misread if jitter were ever added later).
// ============================================================
class EdgeNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int forwardedPackets = 0;
    int localPackets     = 0;
    simtime_t lastLatency = 0;
    bool hasPrior        = false;
    double sumLatency    = 0;
    double sumJitter     = 0;

    int windowCount      = 0;
    simtime_t windowStart = 0;
    int idsAlerts        = 0;
    int idsDropped       = 0;

    // Derivation: 5 IoT nodes send 1 pkt/s each = 5 pkt/s normal max.
    // Threshold set to 5 so any flood packet (6th+) is dropped.
    const int RATE_THRESHOLD = 5;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        if (msg->arrivedOn("fromMIST")) {
            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
            return;
        }

        totalPackets++;

        // Rate window: reset counter every 1 second
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

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        EV << "[Edge] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter << "\n";

        if (intrand(2) == 0) {
            localPackets++;
            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
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
        recordScalar("Edge total packets",     totalPackets);
        recordScalar("Edge dropped packets",   droppedPackets);
        recordScalar("Edge forwarded packets", forwardedPackets);
        recordScalar("Edge local packets",     localPackets);
        recordScalar("Edge IDS alerts",        idsAlerts);
        recordScalar("Edge IDS dropped",       idsDropped);
        recordScalar("Edge avg latency",       totalPackets > 0 ? sumLatency/totalPackets : 0);
        recordScalar("Edge avg jitter",        totalPackets > 0 ? sumJitter/totalPackets  : 0);
        recordScalar("Edge throughput",        totalPackets / simT);
        recordScalar("Edge drop rate",         totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
        recordScalar("Edge detection rate",    totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
    }
};
Define_Module(EdgeNode);

// ============================================================
//  MISTNode — Layer 2 IDS
//
//  RULE 1: Rate > 4 pkt/s → DROP
//    Derivation: Edge lets max 5 through per second.
//    Not all go to the same MIST node (edge[0,1] → mist[0],
//    edge[2] → mist[1]). mist[0] can see at most 3-4 pkts/s
//    under normal load. Threshold = 4.
//
//  RULE 2: Jitter > 0.025s AND rate >= 3 → DROP
//    Derivation: all paths to MIST have identical fixed delay
//    (5ms IoT->Edge + 50ms Edge->MIST = 55ms exactly).
//    Legitimate packet-to-packet jitter is 0ms in this model.
//    Any jitter during a burst means packets from different
//    sources or paths are interleaving — attack signature.
//    Threshold = 0.025s (25ms) gives headroom for scheduling
//    granularity while still being well below one hop (50ms).
//    Rate gate (>= 3) prevents false positives on lone packets.
//
//  FIX 1: hasPrior cold-start guard — first packet jitter = 0
//  FIX 2: jitter threshold raised from 0.05s to 0.025s
//         (counterintuitively LOWER but now rate-gated, so
//          it only fires during confirmed bursts)
//  FIX 3: jitter check gated behind windowCount >= 3
// ============================================================
class MISTNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int forwardedPackets = 0;
    int localPackets     = 0;
    simtime_t lastLatency = 0;
    bool hasPrior        = false;
    double sumLatency    = 0;
    double sumJitter     = 0;

    int windowCount      = 0;
    simtime_t windowStart = 0;
    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;

    const int    RATE_THRESHOLD    = 4;
    const double JITTER_THRESHOLD  = 0.025;  // 25ms — see derivation above
    const int    JITTER_RATE_GATE  = 3;      // only check jitter if burst seen

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        // Rule 1: Rate
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

        // Rule 2: Jitter — only meaningful during a burst
        if (hasPrior && windowCount >= JITTER_RATE_GATE
                && jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[MIST-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " (burst confirmed: rate=" << windowCount << ")"
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("MIST IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        EV << "[MIST] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter << "\n";

        if (intrand(2) == 0) {
            localPackets++;
            send(msg, "toEdge", msg->getArrivalGate()->getIndex());
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
        recordScalar("MIST total packets",     totalPackets);
        recordScalar("MIST dropped packets",   droppedPackets);
        recordScalar("MIST forwarded packets", forwardedPackets);
        recordScalar("MIST local packets",     localPackets);
        recordScalar("MIST IDS alerts",        idsAlerts);
        recordScalar("MIST IDS dropped",       idsDropped);
        recordScalar("MIST IDS rate alerts",   rateAlerts);
        recordScalar("MIST IDS jitter alerts", jitterAlerts);
        recordScalar("MIST avg latency",       totalPackets > 0 ? sumLatency/totalPackets : 0);
        recordScalar("MIST avg jitter",        totalPackets > 0 ? sumJitter/totalPackets  : 0);
        recordScalar("MIST throughput",        totalPackets / simT);
        recordScalar("MIST drop rate",         totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
        recordScalar("MIST detection rate",    totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
    }
};
Define_Module(MISTNode);

// ============================================================
//  FogNode — Layer 3 IDS
//
//  RULE 1: Rate > 3 pkt/s → DROP
//    Derivation: MIST handles some packets locally (~50% by
//    intrand(2)), so Fog sees at most 2-3 forwarded pkts/s
//    under normal load. Threshold = 3.
//
//  RULE 2: Jitter > 0.050s AND rate >= 2 → DROP
//    Derivation: path to Fog = 5+50+100 = 155ms, fixed.
//    Legitimate jitter between consecutive packets = 0ms.
//    Threshold = 0.050s (50ms = one Edge→MIST hop) gives
//    headroom for scheduling granularity in a multi-hop path
//    while catching any real interleaving during a burst.
//    Rate gate (>= 2) prevents false positives on lone packets.
//
//  RULE 3: Latency > 0.300s → DROP
//    Derivation: normal path = 155ms. 300ms = ~2x normal.
//    Any packet taking longer has been queued abnormally
//    or is replayed/delayed by an attacker.
//    This rule is UNCHANGED and valid — it is path-aware.
//
//  FIX 1: hasPrior cold-start guard
//  FIX 2: jitter threshold changed from 0.03s to 0.050s
//  FIX 3: jitter check gated behind windowCount >= 2
// ============================================================
class FogNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int forwardedPackets = 0;
    simtime_t lastLatency = 0;
    bool hasPrior        = false;
    double sumLatency    = 0;
    double sumJitter     = 0;

    int windowCount      = 0;
    simtime_t windowStart = 0;
    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;
    int latencyAlerts    = 0;

    const int    RATE_THRESHOLD    = 3;
    const double JITTER_THRESHOLD  = 0.050;  // 50ms — see derivation above
    const double LATENCY_THRESHOLD = 0.300;  // unchanged — path-aware
    const int    JITTER_RATE_GATE  = 2;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        // Rule 1: Rate
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

        // Rule 2: Jitter — only during a burst
        if (hasPrior && windowCount >= JITTER_RATE_GATE
                && jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[FOG-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " (burst confirmed: rate=" << windowCount << ")"
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Fog IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        // Rule 3: Latency — path-aware, always active
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

        forwardedPackets++;
        EV << "[Fog] pkt #" << totalPackets
           << " latency=" << latency << " jitter=" << jitter
           << " — forwarded to Cloud\n";
        send(msg, "toCloud");
    }

    virtual void finish() override {
        double simT = simTime().dbl();
        EV << "\n=== FOG IDS COMPARATIVE REPORT ===\n";
        recordScalar("Fog total packets",      totalPackets);
        recordScalar("Fog dropped packets",    droppedPackets);
        recordScalar("Fog forwarded packets",  forwardedPackets);
        recordScalar("Fog IDS alerts",         idsAlerts);
        recordScalar("Fog IDS dropped",        idsDropped);
        recordScalar("Fog IDS rate alerts",    rateAlerts);
        recordScalar("Fog IDS jitter alerts",  jitterAlerts);
        recordScalar("Fog IDS latency alerts", latencyAlerts);
        recordScalar("Fog avg latency",        totalPackets > 0 ? sumLatency/totalPackets : 0);
        recordScalar("Fog avg jitter",         totalPackets > 0 ? sumJitter/totalPackets  : 0);
        recordScalar("Fog throughput",         totalPackets / simT);
        recordScalar("Fog drop rate",          totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
        recordScalar("Fog detection rate",     totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
    }
};
Define_Module(FogNode);

// ============================================================
//  CloudNode — Layer 4 IDS
//
//  RULE 1: Rate > 2 pkt/s → DROP
//    Derivation: Fog forwards ~50% of what MIST sends up.
//    Normal Cloud load ≈ 1 pkt/s. Threshold = 2.
//
//  RULE 2: Jitter > 0.100s AND rate >= 2 → DROP
//    Derivation: path = 5+50+100+200 = 355ms, fixed.
//    Legitimate jitter = 0ms between same-source packets.
//    Threshold = 0.100s (100ms = one MIST→Fog hop) gives
//    headroom across the multi-hop path while catching
//    interleaving bursts. Rate gate prevents lone-packet FP.
//
//  RULE 3: Latency > 0.500s → DROP
//    Derivation: normal = 355ms. 500ms = ~1.4x normal.
//    Valid and unchanged.
//
//  RULE 4: Throughput > 1.5x running average → DROP
//    FIX: warm-up guard added (skip R4 until 5 pkts accepted).
//    Without this, packet #2 always looks like a spike because
//    the running average has only 1 data point and is unstable.
//    The exponential moving average (α=0.2) needs ~5 samples
//    to stabilise. Below that sample count, R4 is suppressed.
//
//  FIX 1: hasPrior cold-start guard
//  FIX 2: jitter threshold changed from 0.02s to 0.100s
//  FIX 3: jitter check gated behind windowCount >= 2
//  FIX 4: R4 warm-up guard: acceptedPackets >= 5
// ============================================================
class CloudNode : public cSimpleModule {
  private:
    int totalPackets     = 0;
    int droppedPackets   = 0;
    int acceptedPackets  = 0;
    simtime_t lastLatency = 0;
    bool hasPrior        = false;
    double sumLatency    = 0;
    double sumJitter     = 0;

    int windowCount      = 0;
    simtime_t windowStart = 0;
    double runningAvgThroughput = 0;

    int idsAlerts        = 0;
    int idsDropped       = 0;
    int rateAlerts       = 0;
    int jitterAlerts     = 0;
    int latencyAlerts    = 0;
    int throughputAlerts = 0;

    const int    RATE_THRESHOLD        = 2;
    const double JITTER_THRESHOLD      = 0.100;  // 100ms — see derivation
    const double LATENCY_THRESHOLD     = 0.500;  // unchanged
    const double THROUGHPUT_MULTIPLIER = 1.5;
    const int    JITTER_RATE_GATE      = 2;
    const int    THROUGHPUT_WARMUP     = 5;       // wait for stable EMA

  protected:
    virtual void handleMessage(cMessage *msg) override {
        totalPackets++;

        simtime_t latency = simTime() - msg->getTimestamp();
        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
        lastLatency = latency;
        hasPrior    = true;
        sumLatency += latency.dbl();
        sumJitter  += jitter.dbl();

        double currentThroughput = totalPackets / simTime().dbl();
        if (runningAvgThroughput == 0)
            runningAvgThroughput = currentThroughput;
        else
            runningAvgThroughput = 0.8*runningAvgThroughput + 0.2*currentThroughput;

        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        // Rule 1: Rate
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

        // Rule 2: Jitter — only during a burst
        if (hasPrior && windowCount >= JITTER_RATE_GATE
                && jitter.dbl() > JITTER_THRESHOLD) {
            jitterAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R2: Jitter=" << jitter
               << "s > threshold=" << JITTER_THRESHOLD
               << " (burst confirmed: rate=" << windowCount << ")"
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS jitter alert at", simTime().dbl());
            delete msg;
            return;
        }

        // Rule 3: Latency
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

        // Rule 4: Throughput spike — skip during warm-up
        if (acceptedPackets >= THROUGHPUT_WARMUP
                && runningAvgThroughput > 0
                && currentThroughput > THROUGHPUT_MULTIPLIER * runningAvgThroughput) {
            throughputAlerts++;
            idsAlerts++;
            idsDropped++;
            droppedPackets++;
            EV << "[CLOUD-IDS] ALERT R4: Throughput=" << currentThroughput
               << " > " << THROUGHPUT_MULTIPLIER
               << "x avg=" << runningAvgThroughput
               << " — DROPPED at t=" << simTime() << "\n";
            recordScalar("Cloud IDS throughput alert at", simTime().dbl());
            delete msg;
            return;
        }

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
        recordScalar("Cloud total packets",         totalPackets);
        recordScalar("Cloud accepted packets",      acceptedPackets);
        recordScalar("Cloud dropped packets",       droppedPackets);
        recordScalar("Cloud IDS alerts",            idsAlerts);
        recordScalar("Cloud IDS dropped",           idsDropped);
        recordScalar("Cloud IDS rate alerts",       rateAlerts);
        recordScalar("Cloud IDS jitter alerts",     jitterAlerts);
        recordScalar("Cloud IDS latency alerts",    latencyAlerts);
        recordScalar("Cloud IDS throughput alerts", throughputAlerts);
        recordScalar("Cloud avg latency",           totalPackets > 0 ? sumLatency/totalPackets : 0);
        recordScalar("Cloud avg jitter",            totalPackets > 0 ? sumJitter/totalPackets  : 0);
        recordScalar("Cloud throughput",            totalPackets / simT);
        recordScalar("Cloud drop rate",             totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
        recordScalar("Cloud detection rate",        totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
    }
};
Define_Module(CloudNode);


