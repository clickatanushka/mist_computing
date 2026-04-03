#include <omnetpp.h>
using namespace omnetpp;

// --- IoT Node ---
class IoTNode : public cSimpleModule {
  private:
    int packetCount = 0;
    bool isRogue = false;
    int attackPackets = 0;

  protected:
    virtual void initialize() override {
        scheduleAt(simTime() + 1, new cMessage("timer"));
        isRogue = (getIndex() == 0);  // only iot[0] is attacker
    }
    virtual void handleMessage(cMessage *msg) override {
        if (strcmp(msg->getName(), "SensorData") == 0) {
            simtime_t responseTime = simTime() - msg->getTimestamp();
            EV << "IoT got reply! response time=" << responseTime << "\n";
            delete msg;
        } else {
            packetCount++;
            cMessage *pkt = new cMessage("SensorData");
            pkt->setTimestamp(simTime());
            send(pkt, "out");
            EV << "IoT sent packet #" << packetCount << " at t=" << simTime() << "\n";
            scheduleAt(simTime() + 1, msg);
            if (isRogue && simTime() >= 5) {
                attackPackets++;
                for (int i = 0; i < 9; i++) {
                    cMessage *attack = new cMessage("SensorData");
                    attack->setTimestamp(simTime());
                    send(attack, "out");
                }
                EV << "ATTACKER sending flood packet! total=" << attackPackets << "\n";
            }
        }
    }
};
Define_Module(IoTNode);

// --- Edge Node (first hop from IoT) ---
class EdgeNode : public cSimpleModule {
  private:
    int packetCount  = 0;
    int localCount   = 0;
    int forwardCount = 0;
    simtime_t lastLatency = 0;
    int windowCount = 0;
    simtime_t windowStart = 0;

  protected:
    virtual void handleMessage(cMessage *msg) override {

        // If arriving from MIST (reply path) — just forward back to IoT
        if (msg->arrivedOn("fromMIST")) {
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toIoT", gateIndex);
            return;
        }

        // Arriving from IoT
        packetCount++;

        if (simTime() - windowStart >= 1) {
            windowCount = 0;
            windowStart = simTime();
        }
        windowCount++;

        // DoS detection
        if (windowCount > 5) {
            EV << "EDGE ALERT: DoS attack detected! Blocking packet.\n";
            recordScalar("DoS detected at", simTime().dbl());
            delete msg;
            return;
        }

        simtime_t latency  = simTime() - msg->getTimestamp();
        simtime_t jitter   = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        double throughput  = packetCount / simTime().dbl();

        if (intrand(2) == 0) {
            localCount++;
            EV << "Edge handled LOCALLY  | latency=" << latency
               << " jitter=" << jitter
               << " throughput=" << throughput << "\n";
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toIoT", gateIndex);
        } else {
            forwardCount++;
            EV << "Edge forwarded to MIST | latency=" << latency
               << " jitter=" << jitter
               << " throughput=" << throughput << "\n";
            send(msg, "toMIST");
        }

        EV << "Edge stats: local=" << localCount
           << " forwarded=" << forwardCount << "\n";
    }

    virtual void finish() override {
        recordScalar("Edge avg latency", lastLatency.dbl());
        recordScalar("Edge throughput", packetCount / simTime().dbl());
        recordScalar("Edge local count", localCount);
        recordScalar("Edge forward count", forwardCount);
    }
};
Define_Module(EdgeNode);

// --- MIST Node (second hop) ---
class MISTNode : public cSimpleModule {
  private:
    int packetCount  = 0;
    int localCount   = 0;
    int forwardCount = 0;
    simtime_t lastLatency = 0;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        packetCount++;

        simtime_t latency  = simTime() - msg->getTimestamp();
        simtime_t jitter   = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        double throughput  = packetCount / simTime().dbl();

        EV << "MIST packet #" << packetCount << "\n";
        EV << "  latency    = " << latency    << "s\n";
        EV << "  jitter     = " << jitter     << "s\n";
        EV << "  throughput = " << throughput << " packets/s\n";

        if (intrand(2) == 0) {
            localCount++;
            EV << "MIST handled LOCALLY\n";
            int gateIndex = msg->getArrivalGate()->getIndex();
            send(msg, "toEdge", gateIndex);
        } else {
            forwardCount++;
            EV << "MIST forwarded to FOG\n";
            send(msg, "toFog");
        }

        EV << "MIST stats: local=" << localCount
           << " forwarded=" << forwardCount << "\n";
    }

    virtual void finish() override {
        recordScalar("MIST avg latency", lastLatency.dbl());
        recordScalar("MIST throughput", packetCount / simTime().dbl());
        recordScalar("MIST local count", localCount);
        recordScalar("MIST forward count", forwardCount);
    }
};
Define_Module(MISTNode);

// --- Fog Node (third hop) ---
class FogNode : public cSimpleModule {
  private:
    int packetCount = 0;
    simtime_t lastLatency = 0;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        packetCount++;

        simtime_t latency   = simTime() - msg->getTimestamp();
        simtime_t jitter    = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        double throughput   = packetCount / simTime().dbl();

        EV << "Fog packet #" << packetCount << "\n";
        EV << "  latency    = " << latency    << "s\n";
        EV << "  jitter     = " << jitter     << "s\n";
        EV << "  throughput = " << throughput << " packets/s\n";

        send(msg, "toCloud");
    }

    virtual void finish() override {
        recordScalar("Fog avg latency", lastLatency.dbl());
        recordScalar("Fog throughput", packetCount / simTime().dbl());
    }
};
Define_Module(FogNode);

// --- Cloud Node (final sink) ---
class CloudNode : public cSimpleModule {
  private:
    int packetCount = 0;
    simtime_t lastLatency = 0;

  protected:
    virtual void handleMessage(cMessage *msg) override {
        packetCount++;

        simtime_t latency   = simTime() - msg->getTimestamp();
        simtime_t jitter    = fabs((latency - lastLatency).dbl());
        lastLatency = latency;
        double throughput   = packetCount / simTime().dbl();

        EV << "Cloud packet #" << packetCount << "\n";
        EV << "  latency    = " << latency    << "s\n";
        EV << "  jitter     = " << jitter     << "s\n";
        EV << "  throughput = " << throughput << " packets/s\n";

        delete msg;
    }

    virtual void finish() override {
        recordScalar("Cloud avg latency", lastLatency.dbl());
        recordScalar("Cloud throughput", packetCount / simTime().dbl());
    }
};
Define_Module(CloudNode);
