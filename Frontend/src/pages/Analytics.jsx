import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

const attackData = [
  { name: "SQL Injection", value: 35 },
  { name: "Port Scanning", value: 25 },
  { name: "Brute Force", value: 20 },
  { name: "Malware", value: 20 },
];

const weeklyData = [
  { day: "Mon", attacks: 12 },
  { day: "Tue", attacks: 19 },
  { day: "Wed", attacks: 8 },
  { day: "Thu", attacks: 24 },
  { day: "Fri", attacks: 16 },
  { day: "Sat", attacks: 30 },
  { day: "Sun", attacks: 21 },
];

const COLORS = [
  "#06B6D4",
  "#EF4444",
  "#F59E0B",
  "#8B5CF6",
];

const Analytics = () => {
  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="mb-10">

        <h1 className="text-5xl font-bold mb-2">
          Analytics Dashboard
        </h1>

        <p className="text-gray-400 text-lg">
          Cyber threat analysis and attack insights
        </p>

      </div>

      {/* Top Cards */}
      <div className="grid md:grid-cols-4 gap-6 mb-10">

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">
          <p className="text-gray-400 mb-2">
            Total Threats
          </p>

          <h2 className="text-4xl font-bold text-cyan-400">
            1,284
          </h2>
        </div>

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">
          <p className="text-gray-400 mb-2">
            Critical Alerts
          </p>

          <h2 className="text-4xl font-bold text-red-400">
            87
          </h2>
        </div>

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">
          <p className="text-gray-400 mb-2">
            Blocked Attacks
          </p>

          <h2 className="text-4xl font-bold text-green-400">
            942
          </h2>
        </div>

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">
          <p className="text-gray-400 mb-2">
            Active Nodes
          </p>

          <h2 className="text-4xl font-bold text-purple-400">
            16
          </h2>
        </div>

      </div>

      {/* Charts */}
      <div className="grid lg:grid-cols-2 gap-8">

        {/* Pie Chart */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <h2 className="text-2xl font-bold mb-6">
            Attack Distribution
          </h2>

          <div className="h-[350px]">

            <ResponsiveContainer width="100%" height="100%">

              <PieChart>

                <Pie
                  data={attackData}
                  dataKey="value"
                  outerRadius={120}
                  label
                >

                  {attackData.map((entry, index) => (
                    <Cell
                      key={index}
                      fill={COLORS[index % COLORS.length]}
                    />
                  ))}

                </Pie>

                <Tooltip />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </div>

        {/* Bar Chart */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <h2 className="text-2xl font-bold mb-6">
            Weekly Attack Trends
          </h2>

          <div className="h-[350px]">

            <ResponsiveContainer width="100%" height="100%">

              <BarChart data={weeklyData}>

                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />

                <XAxis dataKey="day" stroke="#9CA3AF" />

                <YAxis stroke="#9CA3AF" />

                <Tooltip />

                <Bar
                  dataKey="attacks"
                  fill="#06B6D4"
                  radius={[8, 8, 0, 0]}
                />

              </BarChart>

            </ResponsiveContainer>

          </div>

        </div>

      </div>

    </div>
  );
};

export default Analytics;