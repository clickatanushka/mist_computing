simple IoTNode {
    gates:
        output out;
        input  in;
}

simple EdgeNode {
    gates:
        input  fromIoT[];
        output toIoT[];
        output toMIST;
        input  fromMIST @loose;
        input  controlIn @loose;
        input  dataIn    @loose;
}

simple MISTNode {
    gates:
        input  fromEdge[];
        output toEdge[];
        output toFog;
        input  controlIn @loose;
}

simple FogNode {
    gates:
        input  fromMIST[];
        output toCloud;
        input  controlIn @loose;
}

simple CloudNode {
    gates:
        input  fromFog;
        input  controlIn @loose;
}

simple CentralController {
    gates:
        input  dataIn @loose;
}

channel IoTToEdge extends ned.DatarateChannel {
    delay = 5ms;
    datarate = 1Mbps;
}

channel EdgeToMIST extends ned.DatarateChannel {
    delay = 50ms;
    datarate = 10Mbps;
}

channel MISTToFog extends ned.DatarateChannel {
    delay = 100ms;
    datarate = 100Mbps;
}

channel FogToCloud extends ned.DatarateChannel {
    delay = 200ms;
    datarate = 1Gbps;
}

network IDSNetwork {
    submodules:
        iot[5]     : IoTNode;
        edge[3]    : EdgeNode;
        mist[2]    : MISTNode;
        fog        : FogNode;
        cloud      : CloudNode;
        controller : CentralController;

    connections allowunconnected:
        iot[0].out --> IoTToEdge --> edge[0].fromIoT++;
        edge[0].toIoT++ --> IoTToEdge --> iot[0].in;

        iot[1].out --> IoTToEdge --> edge[0].fromIoT++;
        edge[0].toIoT++ --> IoTToEdge --> iot[1].in;

        iot[2].out --> IoTToEdge --> edge[1].fromIoT++;
        edge[1].toIoT++ --> IoTToEdge --> iot[2].in;

        iot[3].out --> IoTToEdge --> edge[1].fromIoT++;
        edge[1].toIoT++ --> IoTToEdge --> iot[3].in;

        iot[4].out --> IoTToEdge --> edge[2].fromIoT++;
        edge[2].toIoT++ --> IoTToEdge --> iot[4].in;

        edge[0].toMIST --> EdgeToMIST --> mist[0].fromEdge++;
        edge[1].toMIST --> EdgeToMIST --> mist[0].fromEdge++;
        edge[2].toMIST --> EdgeToMIST --> mist[1].fromEdge++;

        mist[0].toEdge++ --> EdgeToMIST --> edge[0].fromMIST;
        mist[1].toEdge++ --> EdgeToMIST --> edge[2].fromMIST;

        mist[0].toFog --> MISTToFog --> fog.fromMIST++;
        mist[1].toFog --> MISTToFog --> fog.fromMIST++;

        fog.toCloud --> FogToCloud --> cloud.fromFog;
}