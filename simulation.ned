simple IoTNode
{
    gates:
        output out;
        input  fromEdge;        // reply from Edge
}

simple EdgeNode
{
    gates:
        input  fromIoT[];       // packets from IoT devices
        input  fromMIST[];      // replies from MIST (separate gate to avoid index collision)
        output toIoT[];         // replies back to IoT
        output toMIST;          // forward up to MIST
}

simple MISTNode
{
    gates:
        input  fromEdge[];      // packets from Edge
        output toEdge[];        // replies back to Edge
        output toFog;           // forward up to Fog
}

simple FogNode
{
    gates:
        input  fromMIST[];      // packets from MIST
        output toCloud;         // forward up to Cloud
}

simple CloudNode
{
    gates:
        input fromFog[];        // packets from Fog (final sink)
}

network MISTNetwork
{
    @display("bgb=800,550");

    submodules:
        iot[5]: IoTNode {
            @display("p=80,480,row,120");
        }
        edge[3]: EdgeNode {
            @display("p=120,360,row,150");
        }
        mist[2]: MISTNode {
            @display("p=200,240,row,200");
        }
        fog[2]: FogNode {
            @display("p=220,120,row,200");
        }
        cloud: CloudNode {
            @display("p=400,20");
        }

    connections:
        // ── IoT → Edge (5ms) ──────────────────────────────
        iot[0].out --> { delay = 5ms; } --> edge[0].fromIoT++;
        iot[1].out --> { delay = 5ms; } --> edge[0].fromIoT++;
        iot[2].out --> { delay = 5ms; } --> edge[1].fromIoT++;
        iot[3].out --> { delay = 5ms; } --> edge[2].fromIoT++;
        iot[4].out --> { delay = 5ms; } --> edge[2].fromIoT++;

        // ── Edge → IoT replies (5ms) ──────────────────────
        edge[0].toIoT++ --> { delay = 5ms; } --> iot[0].fromEdge;
        edge[0].toIoT++ --> { delay = 5ms; } --> iot[1].fromEdge;
        edge[1].toIoT++ --> { delay = 5ms; } --> iot[2].fromEdge;
        edge[2].toIoT++ --> { delay = 5ms; } --> iot[3].fromEdge;
        edge[2].toIoT++ --> { delay = 5ms; } --> iot[4].fromEdge;

        // ── Edge → MIST (50ms) ────────────────────────────
        edge[0].toMIST --> { delay = 50ms; } --> mist[0].fromEdge++;
        edge[1].toMIST --> { delay = 50ms; } --> mist[0].fromEdge++;
        edge[2].toMIST --> { delay = 50ms; } --> mist[1].fromEdge++;

        // ── MIST → Edge replies via separate fromMIST[] gate (50ms) ──
        mist[0].toEdge++ --> { delay = 50ms; } --> edge[0].fromMIST++;
        mist[0].toEdge++ --> { delay = 50ms; } --> edge[1].fromMIST++;
        mist[1].toEdge++ --> { delay = 50ms; } --> edge[2].fromMIST++;

        // ── MIST → Fog (100ms) ────────────────────────────
        mist[0].toFog --> { delay = 100ms; } --> fog[0].fromMIST++;
        mist[1].toFog --> { delay = 100ms; } --> fog[1].fromMIST++;

        // ── Fog → Cloud (200ms) ───────────────────────────
        fog[0].toCloud --> { delay = 200ms; } --> cloud.fromFog++;
        fog[1].toCloud --> { delay = 200ms; } --> cloud.fromFog++;
}