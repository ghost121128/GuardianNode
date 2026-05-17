import {
  Cpu,
  HardDrive,
  Activity,
  Server,
  ShieldCheck,
  Wifi,
} from "lucide-react";

const Monitor = () => {

  const systems = [
    {
      title: "CPU Usage",
      value: "68%",
      icon: <Cpu size={28} />,
      color: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
    {
      title: "Memory Usage",
      value: "74%",
      icon: <HardDrive size={28} />,
      color: "text-purple-400",
      bg: "bg-purple-500/10",
    },
    {
      title: "Network Traffic",
      value: "1.8 GB/s",
      icon: <Wifi size={28} />,
      color: "text-green-400",
      bg: "bg-green-500/10",
    },
    {
      title: "Threat Detection",
      value: "ACTIVE",
      icon: <ShieldCheck size={28} />,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
  ];

  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="mb-10">

        <h1 className="text-5xl font-bold mb-2">
          System Monitor
        </h1>

        <p className="text-gray-400 text-lg">
          Real-time infrastructure and threat monitoring
        </p>

      </div>

      {/* Top Cards */}
      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">

        {systems.map((system, index) => (

          <div
            key={index}
            className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6 hover:border-cyan-500/40 transition-all duration-300"
          >

            <div
              className={`${system.bg} w-fit p-4 rounded-2xl mb-4`}
            >
              <div className={system.color}>
                {system.icon}
              </div>
            </div>

            <p className="text-gray-400 mb-2">
              {system.title}
            </p>

            <h2
              className={`text-4xl font-bold ${system.color}`}
            >
              {system.value}
            </h2>

          </div>

        ))}

      </div>

      {/* Monitoring Panels */}
      <div className="grid lg:grid-cols-2 gap-8">

        {/* Active Nodes */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <Server className="text-cyan-400" />

            <h2 className="text-2xl font-bold">
              Active Nodes
            </h2>

          </div>

          <div className="space-y-4">

            {[
              "Node-01 Secure",
              "Node-02 Monitoring",
              "Node-03 Protected",
              "Node-04 Active",
            ].map((node, index) => (

              <div
                key={index}
                className="flex justify-between items-center bg-[#111827] border border-gray-800 rounded-2xl p-4"
              >

                <span className="font-medium">
                  {node}
                </span>

                <span className="text-green-400 font-semibold">
                  ONLINE
                </span>

              </div>

            ))}

          </div>

        </div>

        {/* Live Activity */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-6">

            <Activity className="text-green-400" />

            <h2 className="text-2xl font-bold">
              Live Activity
            </h2>

          </div>

          <div className="space-y-4">

            {[
              "Firewall rules updated",
              "New login detected",
              "Threat signature scanned",
              "Traffic spike monitored",
              "Port scan blocked",
            ].map((activity, index) => (

              <div
                key={index}
                className="bg-[#111827] border border-gray-800 rounded-2xl p-4"
              >

                <p className="font-medium">
                  {activity}
                </p>

                <p className="text-gray-500 text-sm mt-1">
                  Just now
                </p>

              </div>

            ))}

          </div>

        </div>

      </div>

    </div>
  );
};

export default Monitor;