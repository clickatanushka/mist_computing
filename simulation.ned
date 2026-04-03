simple IoTNode
{
    gates:
        output out;
        input  fromEdge;        // reply comes back from Edge
}

simple EdgeNode
{
    gates:
        input  fromIoT[];       // packets arriving from IoT
        input  fromMIST[];      // replies arriving from MIST (separate gate!)
        output toIoT[];         // reply path back to IoT
        output toMIST;          // forward path up to MIST
}

simple MISTNode
{
    gates:
        input  fromEdge[];      // packets arriving from Edge
        output toEdge[];        // reply path back to Edge
        output toFog;           // forward path up to Fog
}

simple FogNode
{
    gates:
        input  fromMIST[];
        output toCloud;
}

simple CloudNode
{
    gates:
        input fromFog[];
}

network MISTNetwork
{
    @display("bgb=800,500");
    submodules:
        iot[5]: IoTNode {
            @display("p=80,440,row,120");
        }
        edge[3]: EdgeNode {
            @display("p=120,330,row,150");
        }
        mist[2]: MISTNode {
            @display("p=180,220,row,200");
        }
        fog[2]: FogNode {
            @display("p=220,110,row,200");
        }
        cloud: CloudNode {
            @display("p=400,20");
        }

    connections:
        // IoT --> Edge (5ms)
        iot[0].out --> { delay = 5ms; } --> edge[0].fromIoT++;
        iot[1].out --> { delay = 5ms; } --> edge[0].fromIoT++;
        iot[2].out --> { delay = 5ms; } --> edge[1].fromIoT++;
        iot[3].out --> { delay = 5ms; } --> edge[2].fromIoT++;
        iot[4].out --> { delay = 5ms; } --> edge[2].fromIoT++;

        // Edge --> IoT replies (5ms)
        // toIoT[] index matches fromIoT[] index so gateIndex lookup is correct
        edge[0].toIoT++ --> { delay = 5ms; } --> iot[0].fromEdge;
        edge[0].toIoT++ --> { delay = 5ms; } --> iot[1].fromEdge;
        edge[1].toIoT++ --> { delay = 5ms; } --> iot[2].fromEdge;
        edge[2].toIoT++ --> { delay = 5ms; } --> iot[3].fromEdge;
        edge[2].toIoT++ --> { delay = 5ms; } --> iot[4].fromEdge;

        // Edge --> MIST (50ms)
        edge[0].toMIST --> { delay = 50ms; } --> mist[0].fromEdge++;
        edge[1].toMIST --> { delay = 50ms; } --> mist[0].fromEdge++;
        edge[2].toMIST --> { delay = 50ms; } --> mist[1].fromEdge++;

        // MIST --> Edge replies (50ms) — uses separate fromMIST[] gate on Edge
        // toEdge[] index must match fromEdge[] index on MIST side
        mist[0].toEdge++ --> { delay = 50ms; } --> edge[0].fromMIST++;
        mist[0].toEdge++ --> { delay = 50ms; } --> edge[1].fromMIST++;
        mist[1].toEdge++ --> { delay = 50ms; } --> edge[2].fromMIST++;

        // MIST --> Fog (100ms)
        mist[0].toFog --> { delay = 100ms; } --> fog[0].fromMIST++;
        mist[1].toFog --> { delay = 100ms; } --> fog[1].fromMIST++;

        // Fog --> Cloud (200ms)
        fog[0].toCloud --> { delay = 200ms; } --> cloud.fromFog++;
        fog[1].toCloud --> { delay = 200ms; } --> cloud.fromFog++;
}