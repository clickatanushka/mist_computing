////#include <omnetpp.h>
////#include <cmath>
////using namespace omnetpp;
////
////// ============================================================
//////  IoT Node — sensor device, iot[0] is the rogue attacker
////// ============================================================
////class IoTNode : public cSimpleModule {
////  private:
////    int packetCount  = 0;
////    int attackPackets = 0;
////    bool isRogue     = false;
////
////  protected:
////    virtual void initialize() override {
////        isRogue = (getIndex() == 0);
////        scheduleAt(simTime() + 1, new cMessage("timer"));
////    }
////
////    virtual void handleMessage(cMessage *msg) override {
////        if (strcmp(msg->getName(), "SensorData") == 0) {
////            // reply received back from Edge
////            simtime_t responseTime = simTime() - msg->getTimestamp();
////            EV << "IoT[" << getIndex() << "] got reply! RTT=" << responseTime << "\n";
////            delete msg;
////            return;
////        }
////        // timer fired — send normal packet
////        packetCount++;
////        cMessage *pkt = new cMessage("SensorData");
////        pkt->setTimestamp(simTime());
////        send(pkt, "out");
////        EV << "IoT[" << getIndex() << "] sent packet #" << packetCount << " at t=" << simTime() << "\n";
////        scheduleAt(simTime() + 1, msg);
////
////        // rogue flood after t=5
////        if (isRogue && simTime() >= 5) {
////            attackPackets++;
////            for (int i = 0; i < 9; i++) {
////                cMessage *atk = new cMessage("SensorData");
////                atk->setTimestamp(simTime());
////                send(atk, "out");
////            }
////            EV << "ATTACKER flood #" << attackPackets << " at t=" << simTime() << "\n";
////        }
////    }
////};
////Define_Module(IoTNode);
////
////// ============================================================
//////  Edge Node — Layer 1 IDS
//////  Rule: Rate-based only (packet count per 1s window)
//////  Threshold: > 5 packets/s → alert & drop
////// ============================================================
////class EdgeNode : public cSimpleModule {
////  private:
////    // traffic stats
////    int totalPackets  = 0;
////    int droppedPackets = 0;
////    int forwardedPackets = 0;
////    int localPackets  = 0;
////    simtime_t lastLatency = 0;
////    double sumLatency = 0;
////    double sumJitter  = 0;
////
////    // IDS — rate window
////    int windowCount   = 0;
////    simtime_t windowStart = 0;
////
////    // IDS counters
////    int idsAlerts     = 0;
////    int idsDropped    = 0;
////
////    // thresholds
////    const int RATE_THRESHOLD = 5;   // packets per second
////
////  protected:
////    virtual void handleMessage(cMessage *msg) override {
////
////        // reply arriving from MIST — relay back to IoT
////        if (msg->arrivedOn("fromMIST")) {
////            int gateIndex = msg->getArrivalGate()->getIndex();
////            send(msg, "toIoT", gateIndex);
////            return;
////        }
////
////        totalPackets++;
////
////        // --- IDS Layer 1: Rate-based check ---
////        if (simTime() - windowStart >= 1) {
////            windowCount = 0;
////            windowStart = simTime();
////        }
////        windowCount++;
////
////        if (windowCount > RATE_THRESHOLD) {
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[EDGE-IDS] ALERT: Rate=" << windowCount
////               << "/s exceeds threshold=" << RATE_THRESHOLD
////               << " — packet DROPPED at t=" << simTime() << "\n";
////            recordScalar("Edge IDS alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- normal processing ---
////        simtime_t latency = simTime() - msg->getTimestamp();
////        simtime_t jitter  = fabs((latency - lastLatency).dbl());
////        lastLatency = latency;
////        sumLatency += latency.dbl();
////        sumJitter  += jitter.dbl();
////
////        EV << "[Edge] pkt #" << totalPackets
////           << " latency=" << latency << " jitter=" << jitter << "\n";
////
////        if (intrand(2) == 0) {
////            localPackets++;
////            int gateIndex = msg->getArrivalGate()->getIndex();
////            send(msg, "toIoT", gateIndex);
////            EV << "[Edge] handled LOCALLY\n";
////        } else {
////            forwardedPackets++;
////            send(msg, "toMIST");
////            EV << "[Edge] forwarded to MIST\n";
////        }
////    }
////
////    virtual void finish() override {
////        double simT = simTime().dbl();
////        EV << "\n=== EDGE IDS COMPARATIVE REPORT ===\n";
////        recordScalar("Edge total packets",       totalPackets);
////        recordScalar("Edge dropped packets",     droppedPackets);
////        recordScalar("Edge forwarded packets",   forwardedPackets);
////        recordScalar("Edge local packets",       localPackets);
////        recordScalar("Edge IDS alerts",          idsAlerts);
////        recordScalar("Edge IDS dropped",         idsDropped);
////        recordScalar("Edge avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
////        recordScalar("Edge avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
////        recordScalar("Edge throughput",          totalPackets / simT);
////        recordScalar("Edge drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
////        recordScalar("Edge detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
////    }
////};
////Define_Module(EdgeNode);
////
////// ============================================================
//////  MIST Node — Layer 2 IDS
//////  Rule 1: Rate-based  (> 4 packets/s)
//////  Rule 2: Jitter threshold (jitter > 0.05s)
////// ============================================================
////class MISTNode : public cSimpleModule {
////  private:
////    int totalPackets     = 0;
////    int droppedPackets   = 0;
////    int forwardedPackets = 0;
////    int localPackets     = 0;
////    simtime_t lastLatency = 0;
////    double sumLatency    = 0;
////    double sumJitter     = 0;
////
////    // IDS — rate window
////    int windowCount      = 0;
////    simtime_t windowStart = 0;
////
////    // IDS counters
////    int idsAlerts        = 0;
////    int idsDropped       = 0;
////    int rateAlerts       = 0;
////    int jitterAlerts     = 0;
////
////    // thresholds
////    const int    RATE_THRESHOLD   = 4;     // stricter than Edge
////    const double JITTER_THRESHOLD = 0.05;  // seconds
////
////  protected:
////    virtual void handleMessage(cMessage *msg) override {
////        totalPackets++;
////
////        simtime_t latency = simTime() - msg->getTimestamp();
////        simtime_t jitter  = fabs((latency - lastLatency).dbl());
////        lastLatency = latency;
////        sumLatency += latency.dbl();
////        sumJitter  += jitter.dbl();
////
////        // --- IDS Layer 2, Rule 1: Rate check ---
////        if (simTime() - windowStart >= 1) {
////            windowCount = 0;
////            windowStart = simTime();
////        }
////        windowCount++;
////
////        if (windowCount > RATE_THRESHOLD) {
////            rateAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[MIST-IDS] ALERT R1: Rate=" << windowCount
////               << "/s > threshold=" << RATE_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("MIST IDS rate alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 2, Rule 2: Jitter check ---
////        if (jitter.dbl() > JITTER_THRESHOLD) {
////            jitterAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[MIST-IDS] ALERT R2: Jitter=" << jitter
////               << "s > threshold=" << JITTER_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("MIST IDS jitter alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- normal processing ---
////        EV << "[MIST] pkt #" << totalPackets
////           << " latency=" << latency << " jitter=" << jitter << "\n";
////
////        if (intrand(2) == 0) {
////            localPackets++;
////            int gateIndex = msg->getArrivalGate()->getIndex();
////            send(msg, "toEdge", gateIndex);
////            EV << "[MIST] handled LOCALLY\n";
////        } else {
////            forwardedPackets++;
////            send(msg, "toFog");
////            EV << "[MIST] forwarded to FOG\n";
////        }
////    }
////
////    virtual void finish() override {
////        double simT = simTime().dbl();
////        EV << "\n=== MIST IDS COMPARATIVE REPORT ===\n";
////        recordScalar("MIST total packets",       totalPackets);
////        recordScalar("MIST dropped packets",     droppedPackets);
////        recordScalar("MIST forwarded packets",   forwardedPackets);
////        recordScalar("MIST local packets",       localPackets);
////        recordScalar("MIST IDS alerts",          idsAlerts);
////        recordScalar("MIST IDS dropped",         idsDropped);
////        recordScalar("MIST IDS rate alerts",     rateAlerts);
////        recordScalar("MIST IDS jitter alerts",   jitterAlerts);
////        recordScalar("MIST avg latency",         totalPackets > 0 ? sumLatency / totalPackets : 0);
////        recordScalar("MIST avg jitter",          totalPackets > 0 ? sumJitter  / totalPackets : 0);
////        recordScalar("MIST throughput",          totalPackets / simT);
////        recordScalar("MIST drop rate",           totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
////        recordScalar("MIST detection rate",      totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
////    }
////};
////Define_Module(MISTNode);
////
////// ============================================================
//////  Fog Node — Layer 3 IDS
//////  Rule 1: Rate-based  (> 3 packets/s)
//////  Rule 2: Jitter threshold (> 0.03s)
//////  Rule 3: Latency threshold (> 0.3s)
////// ============================================================
////class FogNode : public cSimpleModule {
////  private:
////    int totalPackets     = 0;
////    int droppedPackets   = 0;
////    int forwardedPackets = 0;
////    simtime_t lastLatency = 0;
////    double sumLatency    = 0;
////    double sumJitter     = 0;
////
////    // IDS — rate window
////    int windowCount      = 0;
////    simtime_t windowStart = 0;
////
////    // IDS counters
////    int idsAlerts        = 0;
////    int idsDropped       = 0;
////    int rateAlerts       = 0;
////    int jitterAlerts     = 0;
////    int latencyAlerts    = 0;
////
////    // thresholds
////    const int    RATE_THRESHOLD    = 3;
////    const double JITTER_THRESHOLD  = 0.03;
////    const double LATENCY_THRESHOLD = 0.3;   // seconds
////
////  protected:
////    virtual void handleMessage(cMessage *msg) override {
////        totalPackets++;
////
////        simtime_t latency = simTime() - msg->getTimestamp();
////        simtime_t jitter  = fabs((latency - lastLatency).dbl());
////        lastLatency = latency;
////        sumLatency += latency.dbl();
////        sumJitter  += jitter.dbl();
////
////        // --- IDS Layer 3, Rule 1: Rate check ---
////        if (simTime() - windowStart >= 1) {
////            windowCount = 0;
////            windowStart = simTime();
////        }
////        windowCount++;
////
////        if (windowCount > RATE_THRESHOLD) {
////            rateAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[FOG-IDS] ALERT R1: Rate=" << windowCount
////               << "/s > threshold=" << RATE_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Fog IDS rate alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 3, Rule 2: Jitter check ---
////        if (jitter.dbl() > JITTER_THRESHOLD) {
////            jitterAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[FOG-IDS] ALERT R2: Jitter=" << jitter
////               << "s > threshold=" << JITTER_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Fog IDS jitter alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 3, Rule 3: Latency check ---
////        if (latency.dbl() > LATENCY_THRESHOLD) {
////            latencyAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[FOG-IDS] ALERT R3: Latency=" << latency
////               << "s > threshold=" << LATENCY_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Fog IDS latency alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- normal processing — forward to Cloud ---
////        forwardedPackets++;
////        EV << "[Fog] pkt #" << totalPackets
////           << " latency=" << latency << " jitter=" << jitter
////           << " — forwarded to Cloud\n";
////        send(msg, "toCloud");
////    }
////
////    virtual void finish() override {
////        double simT = simTime().dbl();
////        EV << "\n=== FOG IDS COMPARATIVE REPORT ===\n";
////        recordScalar("Fog total packets",        totalPackets);
////        recordScalar("Fog dropped packets",      droppedPackets);
////        recordScalar("Fog forwarded packets",    forwardedPackets);
////        recordScalar("Fog IDS alerts",           idsAlerts);
////        recordScalar("Fog IDS dropped",          idsDropped);
////        recordScalar("Fog IDS rate alerts",      rateAlerts);
////        recordScalar("Fog IDS jitter alerts",    jitterAlerts);
////        recordScalar("Fog IDS latency alerts",   latencyAlerts);
////        recordScalar("Fog avg latency",          totalPackets > 0 ? sumLatency / totalPackets : 0);
////        recordScalar("Fog avg jitter",           totalPackets > 0 ? sumJitter  / totalPackets : 0);
////        recordScalar("Fog throughput",           totalPackets / simT);
////        recordScalar("Fog drop rate",            totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
////        recordScalar("Fog detection rate",       totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
////    }
////};
////Define_Module(FogNode);
////
////// ============================================================
//////  Cloud Node — Layer 4 IDS (most comprehensive)
//////  Rule 1: Rate-based         (> 2 packets/s)
//////  Rule 2: Jitter threshold   (> 0.02s)
//////  Rule 3: Latency threshold  (> 0.5s)
//////  Rule 4: Throughput anomaly (throughput > 1.5x running average)
////// ============================================================
////class CloudNode : public cSimpleModule {
////  private:
////    int totalPackets     = 0;
////    int droppedPackets   = 0;
////    int acceptedPackets  = 0;
////    simtime_t lastLatency = 0;
////    double sumLatency    = 0;
////    double sumJitter     = 0;
////
////    // IDS — rate window
////    int windowCount      = 0;
////    simtime_t windowStart = 0;
////
////    // throughput anomaly tracking
////    double runningAvgThroughput = 0;
////
////    // IDS counters
////    int idsAlerts        = 0;
////    int idsDropped       = 0;
////    int rateAlerts       = 0;
////    int jitterAlerts     = 0;
////    int latencyAlerts    = 0;
////    int throughputAlerts = 0;
////
////    // thresholds
////    const int    RATE_THRESHOLD        = 2;
////    const double JITTER_THRESHOLD      = 0.02;
////    const double LATENCY_THRESHOLD     = 0.5;
////    const double THROUGHPUT_MULTIPLIER = 1.5;
////
////  protected:
////    virtual void handleMessage(cMessage *msg) override {
////        totalPackets++;
////
////        simtime_t latency = simTime() - msg->getTimestamp();
////        simtime_t jitter  = fabs((latency - lastLatency).dbl());
////        lastLatency = latency;
////        sumLatency += latency.dbl();
////        sumJitter  += jitter.dbl();
////
////        double currentThroughput = totalPackets / simTime().dbl();
////        // update running average (exponential moving average)
////        if (runningAvgThroughput == 0)
////            runningAvgThroughput = currentThroughput;
////        else
////            runningAvgThroughput = 0.8 * runningAvgThroughput + 0.2 * currentThroughput;
////
////        // --- IDS Layer 4, Rule 1: Rate check ---
////        if (simTime() - windowStart >= 1) {
////            windowCount = 0;
////            windowStart = simTime();
////        }
////        windowCount++;
////
////        if (windowCount > RATE_THRESHOLD) {
////            rateAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[CLOUD-IDS] ALERT R1: Rate=" << windowCount
////               << "/s > threshold=" << RATE_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Cloud IDS rate alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 4, Rule 2: Jitter check ---
////        if (jitter.dbl() > JITTER_THRESHOLD) {
////            jitterAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[CLOUD-IDS] ALERT R2: Jitter=" << jitter
////               << "s > threshold=" << JITTER_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Cloud IDS jitter alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 4, Rule 3: Latency check ---
////        if (latency.dbl() > LATENCY_THRESHOLD) {
////            latencyAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[CLOUD-IDS] ALERT R3: Latency=" << latency
////               << "s > threshold=" << LATENCY_THRESHOLD
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Cloud IDS latency alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- IDS Layer 4, Rule 4: Throughput anomaly check ---
////        if (runningAvgThroughput > 0 &&
////            currentThroughput > THROUGHPUT_MULTIPLIER * runningAvgThroughput) {
////            throughputAlerts++;
////            idsAlerts++;
////            idsDropped++;
////            droppedPackets++;
////            EV << "[CLOUD-IDS] ALERT R4: Throughput=" << currentThroughput
////               << " > " << THROUGHPUT_MULTIPLIER << "x avg=" << runningAvgThroughput
////               << " — DROPPED at t=" << simTime() << "\n";
////            recordScalar("Cloud IDS throughput alert at", simTime().dbl());
////            delete msg;
////            return;
////        }
////
////        // --- packet accepted ---
////        acceptedPackets++;
////        EV << "[Cloud] pkt #" << totalPackets
////           << " ACCEPTED | latency=" << latency
////           << " jitter=" << jitter
////           << " throughput=" << currentThroughput << "\n";
////        delete msg;
////    }
////
////    virtual void finish() override {
////        double simT = simTime().dbl();
////        EV << "\n=== CLOUD IDS COMPARATIVE REPORT ===\n";
////        recordScalar("Cloud total packets",          totalPackets);
////        recordScalar("Cloud accepted packets",       acceptedPackets);
////        recordScalar("Cloud dropped packets",        droppedPackets);
////        recordScalar("Cloud IDS alerts",             idsAlerts);
////        recordScalar("Cloud IDS dropped",            idsDropped);
////        recordScalar("Cloud IDS rate alerts",        rateAlerts);
////        recordScalar("Cloud IDS jitter alerts",      jitterAlerts);
////        recordScalar("Cloud IDS latency alerts",     latencyAlerts);
////        recordScalar("Cloud IDS throughput alerts",  throughputAlerts);
////        recordScalar("Cloud avg latency",            totalPackets > 0 ? sumLatency / totalPackets : 0);
////        recordScalar("Cloud avg jitter",             totalPackets > 0 ? sumJitter  / totalPackets : 0);
////        recordScalar("Cloud throughput",             totalPackets / simT);
////        recordScalar("Cloud drop rate",              totalPackets > 0 ? (double)droppedPackets / totalPackets : 0);
////        recordScalar("Cloud detection rate",         totalPackets > 0 ? (double)idsAlerts / totalPackets : 0);
////    }
////};
////Define_Module(CloudNode);
//
//
//#include <omnetpp.h>
//#include <cmath>
//using namespace omnetpp;
//
//// ============================================================
////  IoTNode — sensor device
////  iot[0] doubles as the rogue attacker after t=5s
////  No changes needed from original.
//// ============================================================
//class IoTNode : public cSimpleModule {
//  private:
//    int packetCount   = 0;
//    int attackPackets = 0;
//    bool isRogue      = false;
//
//  protected:
//    virtual void initialize() override {
//        isRogue = (getIndex() == 0);
//        scheduleAt(simTime() + 1, new cMessage("timer"));
//    }
//
//    virtual void handleMessage(cMessage *msg) override {
//        if (strcmp(msg->getName(), "SensorData") == 0) {
//            simtime_t rtt = simTime() - msg->getTimestamp();
//            EV << "IoT[" << getIndex() << "] got reply! RTT=" << rtt << "\n";
//            delete msg;
//            return;
//        }
//        packetCount++;
//        cMessage *pkt = new cMessage("SensorData");
//        pkt->setTimestamp(simTime());
//        send(pkt, "out");
////
////        cMessage *pkt = new cMessage("SensorData");
////        pkt->setTimestamp(simTime());// ADD THESE 👇
////        pkt->addPar("srcId") = getIndex();
////        pkt->addPar("isAttack") = false;
////        send(pkt, "out");
//        EV << "IoT[" << getIndex() << "] sent packet #" << packetCount
//           << " at t=" << simTime() << "\n";
//        scheduleAt(simTime() + 1, msg);
//
//        if (isRogue && simTime() >= 5) {
//            attackPackets++;
//            for (int i = 0; i < 9; i++) {
//                cMessage *atk = new cMessage("SensorData");
//                atk->setTimestamp(simTime());
//                send(atk, "out");
////                cMessage *atk = new cMessage("SensorData");
////                atk->setTimestamp(simTime());
////
////                // ADD THESE 👇
////                atk->addPar("srcId") = getIndex();
////                atk->addPar("isAttack") = true;
////
////                send(atk, "out");
//            }
//            EV << "ATTACKER flood #" << attackPackets
//               << " at t=" << simTime() << "\n";
//        }
//    }
//};
//Define_Module(IoTNode);
//
//// ============================================================
////  EdgeNode — Layer 1 IDS
////
////  RULE: Rate > 5 pkt/s → DROP
////
////  WHY no jitter check here:
////    Edge sees raw IoT traffic arriving at exactly 5ms latency
////    every time (fixed channel delay, no queuing in this model).
////    Jitter is always 0 for legitimate single-source packets.
////    Adding a jitter check here would only add complexity with
////    no detection benefit.
////
////  FIX applied: hasPrior cold-start guard (prevents jitter=0.005
////    on packet #1 being misread if jitter were ever added later).
//// ============================================================
//class EdgeNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int forwardedPackets = 0;
//    int localPackets     = 0;
//    simtime_t lastLatency = 0;
//    bool hasPrior        = false;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//
//    // Derivation: 5 IoT nodes send 1 pkt/s each = 5 pkt/s normal max.
//    // Threshold set to 5 so any flood packet (6th+) is dropped.
//    const int RATE_THRESHOLD = 5;
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        if (msg->arrivedOn("fromMIST")) {
//            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
//            return;
//        }
//
//        totalPackets++;
//
//        // Rate window: reset counter every 1 second
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
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
//        lastLatency = latency;
//        hasPrior    = true;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        EV << "[Edge] pkt #" << totalPackets
//           << " latency=" << latency << " jitter=" << jitter << "\n";
//
//        if (intrand(2) == 0) {
//            localPackets++;
//            send(msg, "toIoT", msg->getArrivalGate()->getIndex());
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
//        recordScalar("Edge total packets",     totalPackets);
//        recordScalar("Edge dropped packets",   droppedPackets);
//        recordScalar("Edge forwarded packets", forwardedPackets);
//        recordScalar("Edge local packets",     localPackets);
//        recordScalar("Edge IDS alerts",        idsAlerts);
//        recordScalar("Edge IDS dropped",       idsDropped);
//        recordScalar("Edge avg latency",       totalPackets > 0 ? sumLatency/totalPackets : 0);
//        recordScalar("Edge avg jitter",        totalPackets > 0 ? sumJitter/totalPackets  : 0);
//        recordScalar("Edge throughput",        totalPackets / simT);
//        recordScalar("Edge drop rate",         totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
//        recordScalar("Edge detection rate",    totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
//    }
//};
//Define_Module(EdgeNode);
//
//// ============================================================
////  MISTNode — Layer 2 IDS
////
////  RULE 1: Rate > 4 pkt/s → DROP
////    Derivation: Edge lets max 5 through per second.
////    Not all go to the same MIST node (edge[0,1] → mist[0],
////    edge[2] → mist[1]). mist[0] can see at most 3-4 pkts/s
////    under normal load. Threshold = 4.
////
////  RULE 2: Jitter > 0.025s AND rate >= 3 → DROP
////    Derivation: all paths to MIST have identical fixed delay
////    (5ms IoT->Edge + 50ms Edge->MIST = 55ms exactly).
////    Legitimate packet-to-packet jitter is 0ms in this model.
////    Any jitter during a burst means packets from different
////    sources or paths are interleaving — attack signature.
////    Threshold = 0.025s (25ms) gives headroom for scheduling
////    granularity while still being well below one hop (50ms).
////    Rate gate (>= 3) prevents false positives on lone packets.
////
////  FIX 1: hasPrior cold-start guard — first packet jitter = 0
////  FIX 2: jitter threshold raised from 0.05s to 0.025s
////         (counterintuitively LOWER but now rate-gated, so
////          it only fires during confirmed bursts)
////  FIX 3: jitter check gated behind windowCount >= 3
//// ============================================================
//class MISTNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int forwardedPackets = 0;
//    int localPackets     = 0;
//    simtime_t lastLatency = 0;
//    bool hasPrior        = false;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//
//    const int    RATE_THRESHOLD    = 4;
//    const double JITTER_THRESHOLD  = 0.025;  // 25ms — see derivation above
//    const int    JITTER_RATE_GATE  = 3;      // only check jitter if burst seen
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
//        lastLatency = latency;
//        hasPrior    = true;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        // Rule 1: Rate
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
//        // Rule 2: Jitter — only meaningful during a burst
//        if (hasPrior && windowCount >= JITTER_RATE_GATE
//                && jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[MIST-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " (burst confirmed: rate=" << windowCount << ")"
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("MIST IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        EV << "[MIST] pkt #" << totalPackets
//           << " latency=" << latency << " jitter=" << jitter << "\n";
//
//        if (intrand(2) == 0) {
//            localPackets++;
//            send(msg, "toEdge", msg->getArrivalGate()->getIndex());
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
//        recordScalar("MIST total packets",     totalPackets);
//        recordScalar("MIST dropped packets",   droppedPackets);
//        recordScalar("MIST forwarded packets", forwardedPackets);
//        recordScalar("MIST local packets",     localPackets);
//        recordScalar("MIST IDS alerts",        idsAlerts);
//        recordScalar("MIST IDS dropped",       idsDropped);
//        recordScalar("MIST IDS rate alerts",   rateAlerts);
//        recordScalar("MIST IDS jitter alerts", jitterAlerts);
//        recordScalar("MIST avg latency",       totalPackets > 0 ? sumLatency/totalPackets : 0);
//        recordScalar("MIST avg jitter",        totalPackets > 0 ? sumJitter/totalPackets  : 0);
//        recordScalar("MIST throughput",        totalPackets / simT);
//        recordScalar("MIST drop rate",         totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
//        recordScalar("MIST detection rate",    totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
//    }
//};
//Define_Module(MISTNode);
//
//// ============================================================
////  FogNode — Layer 3 IDS
////
////  RULE 1: Rate > 3 pkt/s → DROP
////    Derivation: MIST handles some packets locally (~50% by
////    intrand(2)), so Fog sees at most 2-3 forwarded pkts/s
////    under normal load. Threshold = 3.
////
////  RULE 2: Jitter > 0.050s AND rate >= 2 → DROP
////    Derivation: path to Fog = 5+50+100 = 155ms, fixed.
////    Legitimate jitter between consecutive packets = 0ms.
////    Threshold = 0.050s (50ms = one Edge→MIST hop) gives
////    headroom for scheduling granularity in a multi-hop path
////    while catching any real interleaving during a burst.
////    Rate gate (>= 2) prevents false positives on lone packets.
////
////  RULE 3: Latency > 0.300s → DROP
////    Derivation: normal path = 155ms. 300ms = ~2x normal.
////    Any packet taking longer has been queued abnormally
////    or is replayed/delayed by an attacker.
////    This rule is UNCHANGED and valid — it is path-aware.
////
////  FIX 1: hasPrior cold-start guard
////  FIX 2: jitter threshold changed from 0.03s to 0.050s
////  FIX 3: jitter check gated behind windowCount >= 2
//// ============================================================
//class FogNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int forwardedPackets = 0;
//    simtime_t lastLatency = 0;
//    bool hasPrior        = false;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//    int latencyAlerts    = 0;
//
//    const int    RATE_THRESHOLD    = 3;
//    const double JITTER_THRESHOLD  = 0.050;  // 50ms — see derivation above
//    const double LATENCY_THRESHOLD = 0.300;  // unchanged — path-aware
//    const int    JITTER_RATE_GATE  = 2;
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
//        lastLatency = latency;
//        hasPrior    = true;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        // Rule 1: Rate
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
//        // Rule 2: Jitter — only during a burst
//        if (hasPrior && windowCount >= JITTER_RATE_GATE
//                && jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[FOG-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " (burst confirmed: rate=" << windowCount << ")"
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Fog IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // Rule 3: Latency — path-aware, always active
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
//        recordScalar("Fog total packets",      totalPackets);
//        recordScalar("Fog dropped packets",    droppedPackets);
//        recordScalar("Fog forwarded packets",  forwardedPackets);
//        recordScalar("Fog IDS alerts",         idsAlerts);
//        recordScalar("Fog IDS dropped",        idsDropped);
//        recordScalar("Fog IDS rate alerts",    rateAlerts);
//        recordScalar("Fog IDS jitter alerts",  jitterAlerts);
//        recordScalar("Fog IDS latency alerts", latencyAlerts);
//        recordScalar("Fog avg latency",        totalPackets > 0 ? sumLatency/totalPackets : 0);
//        recordScalar("Fog avg jitter",         totalPackets > 0 ? sumJitter/totalPackets  : 0);
//        recordScalar("Fog throughput",         totalPackets / simT);
//        recordScalar("Fog drop rate",          totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
//        recordScalar("Fog detection rate",     totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
//    }
//};
//Define_Module(FogNode);
//
//// ============================================================
////  CloudNode — Layer 4 IDS
////
////  RULE 1: Rate > 2 pkt/s → DROP
////    Derivation: Fog forwards ~50% of what MIST sends up.
////    Normal Cloud load ≈ 1 pkt/s. Threshold = 2.
////
////  RULE 2: Jitter > 0.100s AND rate >= 2 → DROP
////    Derivation: path = 5+50+100+200 = 355ms, fixed.
////    Legitimate jitter = 0ms between same-source packets.
////    Threshold = 0.100s (100ms = one MIST→Fog hop) gives
////    headroom across the multi-hop path while catching
////    interleaving bursts. Rate gate prevents lone-packet FP.
////
////  RULE 3: Latency > 0.500s → DROP
////    Derivation: normal = 355ms. 500ms = ~1.4x normal.
////    Valid and unchanged.
////
////  RULE 4: Throughput > 1.5x running average → DROP
////    FIX: warm-up guard added (skip R4 until 5 pkts accepted).
////    Without this, packet #2 always looks like a spike because
////    the running average has only 1 data point and is unstable.
////    The exponential moving average (α=0.2) needs ~5 samples
////    to stabilise. Below that sample count, R4 is suppressed.
////
////  FIX 1: hasPrior cold-start guard
////  FIX 2: jitter threshold changed from 0.02s to 0.100s
////  FIX 3: jitter check gated behind windowCount >= 2
////  FIX 4: R4 warm-up guard: acceptedPackets >= 5
//// ============================================================
//class CloudNode : public cSimpleModule {
//  private:
//    int totalPackets     = 0;
//    int droppedPackets   = 0;
//    int acceptedPackets  = 0;
//    simtime_t lastLatency = 0;
//    bool hasPrior        = false;
//    double sumLatency    = 0;
//    double sumJitter     = 0;
//
//    int windowCount      = 0;
//    simtime_t windowStart = 0;
//    double runningAvgThroughput = 0;
//
//    int idsAlerts        = 0;
//    int idsDropped       = 0;
//    int rateAlerts       = 0;
//    int jitterAlerts     = 0;
//    int latencyAlerts    = 0;
//    int throughputAlerts = 0;
//
//    const int    RATE_THRESHOLD        = 2;
//    const double JITTER_THRESHOLD      = 0.100;  // 100ms — see derivation
//    const double LATENCY_THRESHOLD     = 0.500;  // unchanged
//    const double THROUGHPUT_MULTIPLIER = 1.5;
//    const int    JITTER_RATE_GATE      = 2;
//    const int    THROUGHPUT_WARMUP     = 5;       // wait for stable EMA
//
//  protected:
//    virtual void handleMessage(cMessage *msg) override {
//        totalPackets++;
//
//        simtime_t latency = simTime() - msg->getTimestamp();
//        simtime_t jitter  = hasPrior ? fabs((latency - lastLatency).dbl()) : 0;
//        lastLatency = latency;
//        hasPrior    = true;
//        sumLatency += latency.dbl();
//        sumJitter  += jitter.dbl();
//
//        double currentThroughput = totalPackets / simTime().dbl();
//        if (runningAvgThroughput == 0)
//            runningAvgThroughput = currentThroughput;
//        else
//            runningAvgThroughput = 0.8*runningAvgThroughput + 0.2*currentThroughput;
//
//        if (simTime() - windowStart >= 1) {
//            windowCount = 0;
//            windowStart = simTime();
//        }
//        windowCount++;
//
//        // Rule 1: Rate
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
//        // Rule 2: Jitter — only during a burst
//        if (hasPrior && windowCount >= JITTER_RATE_GATE
//                && jitter.dbl() > JITTER_THRESHOLD) {
//            jitterAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R2: Jitter=" << jitter
//               << "s > threshold=" << JITTER_THRESHOLD
//               << " (burst confirmed: rate=" << windowCount << ")"
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS jitter alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
//        // Rule 3: Latency
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
//        // Rule 4: Throughput spike — skip during warm-up
//        if (acceptedPackets >= THROUGHPUT_WARMUP
//                && runningAvgThroughput > 0
//                && currentThroughput > THROUGHPUT_MULTIPLIER * runningAvgThroughput) {
//            throughputAlerts++;
//            idsAlerts++;
//            idsDropped++;
//            droppedPackets++;
//            EV << "[CLOUD-IDS] ALERT R4: Throughput=" << currentThroughput
//               << " > " << THROUGHPUT_MULTIPLIER
//               << "x avg=" << runningAvgThroughput
//               << " — DROPPED at t=" << simTime() << "\n";
//            recordScalar("Cloud IDS throughput alert at", simTime().dbl());
//            delete msg;
//            return;
//        }
//
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
//        recordScalar("Cloud total packets",         totalPackets);
//        recordScalar("Cloud accepted packets",      acceptedPackets);
//        recordScalar("Cloud dropped packets",       droppedPackets);
//        recordScalar("Cloud IDS alerts",            idsAlerts);
//        recordScalar("Cloud IDS dropped",           idsDropped);
//        recordScalar("Cloud IDS rate alerts",       rateAlerts);
//        recordScalar("Cloud IDS jitter alerts",     jitterAlerts);
//        recordScalar("Cloud IDS latency alerts",    latencyAlerts);
//        recordScalar("Cloud IDS throughput alerts", throughputAlerts);
//        recordScalar("Cloud avg latency",           totalPackets > 0 ? sumLatency/totalPackets : 0);
//        recordScalar("Cloud avg jitter",            totalPackets > 0 ? sumJitter/totalPackets  : 0);
//        recordScalar("Cloud throughput",            totalPackets / simT);
//        recordScalar("Cloud drop rate",             totalPackets > 0 ? (double)droppedPackets/totalPackets : 0);
//        recordScalar("Cloud detection rate",        totalPackets > 0 ? (double)idsAlerts/totalPackets : 0);
//    }
//};
//Define_Module(CloudNode);
//
//



/*
 * =============================================================
 *  Multi-Attack Adaptive IDS — OMNeT++ Simulation
 *  Attacks: DDoS, MitM, SQL Injection
 *
 *  Architecture
 *  ────────────
 *  IoTNode  →  EdgeNode  →  MISTNode  →  FogNode  →  CloudNode
 *                ↑               ↑            ↑            ↑
 *                └───────────────┴────────────┴────────────┘
 *                            CentralController
 *                     (reads ids_profiles.json, classifies
 *                      traffic, pushes ThreatMode to all layers)
 *
 *  ThreatMode enum: MODE_DDOS | MODE_MITM | MODE_SQLI
 *
 *  Each layer holds 3 ThresholdProfile structs — one per mode.
 *  The active profile is swapped atomically when the controller
 *  sends a "ModeChange" control message.
 *
 *  Detection rules per mode
 *  ────────────────────────
 *  DDOS  → primary:rate,    secondary:jitter
 *  MITM  → primary:latency, secondary:jitter
 *  SQLI  → primary:payload, secondary:entropy
 *
 *  Thresholds are loaded from  ids_profiles.json  at startup.
 *  If the file is missing, hardcoded fallbacks are used.
 *
 *  Run the Python trainer first:
 *    python train_ids_classifier.py
 *  Place ids_profiles.json next to the simulation binary.
 * =============================================================
 */

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
