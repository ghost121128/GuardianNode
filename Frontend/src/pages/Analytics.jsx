import {
  ShieldCheck,
  Activity,
  AlertTriangle,
  TrendingUp,
} from "lucide-react";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  Tooltip,
  BarChart,
  Bar,
} from "recharts";

const threatData = [
  { day: "Mon", threats: 12 },
  { day: "Tue", threats: 19 },
  { day: "Wed", threats: 15 },
  { day: "Thu", threats: 28 },
  { day: "Fri", threats: 22 },
  { day: "Sat", threats: 31 },
  { day: "Sun", threats: 26 },
];

const attackSources = [
  { country: "USA", attacks: 120 },
  { country: "Russia", attacks: 98 },
  { country: "China", attacks: 84 },
  { country: "Germany", attacks: 62 },
];

const Analytics = ({

  darkMode,

}) => {

  return (

    <div className={`min-h-screen p-8 transition-all duration-500 ${
      darkMode

        ? "bg-[#040816] text-white"

        : "bg-white text-gray-900"
    }`}>

      {/* Header */}

      <div className="flex items-center justify-between mb-10">

        <div>

          <h1 className="text-5xl font-black mb-2">

            Analytics

          </h1>

          <p className={`${
            darkMode

              ? "text-gray-400"

              : "text-gray-500"
          }`}>

            Cybersecurity insights and monitoring statistics

          </p>

        </div>

        <div className={`border rounded-2xl px-5 py-3 flex items-center gap-3 ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <TrendingUp className="text-cyan-400" />

          <span className="text-cyan-400 font-semibold">

            LIVE ANALYTICS

          </span>

        </div>

      </div>

      {/* Top Stats */}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-10">

        {[
          {
            title: "Threats Blocked",
            value: "332",
            icon: <ShieldCheck className="text-cyan-400" />,
            color: "text-cyan-400",
          },

          {
            title: "Critical Alerts",
            value: "94",
            icon: <AlertTriangle className="text-red-400" />,
            color: "text-red-400",
          },

          {
            title: "Traffic Analysis",
            value: "2.4TB",
            icon: <Activity className="text-green-400" />,
            color: "text-green-400",
          },

          {
            title: "System Efficiency",
            value: "98%",
            icon: <TrendingUp className="text-orange-400" />,
            color: "text-orange-400",
          },
        ].map((card, index) => (

          <div
            key={index}

            className={`backdrop-blur-xl border rounded-[32px] p-6 shadow-xl ${
              darkMode

                ? "bg-[#0B1120]/80 border-[#1E293B]"

                : "bg-gray-100 border-gray-200"
            }`}
          >

            <div className="flex items-center justify-between mb-6">

              <div className={`p-4 rounded-2xl ${
                darkMode

                  ? "bg-black/20"

                  : "bg-black/5"
              }`}>

                {card.icon}

              </div>

            </div>

            <p className={`text-sm mb-2 ${
              darkMode

                ? "text-gray-400"

                : "text-gray-500"
            }`}>

              {card.title}

            </p>

            <h2 className={`text-4xl font-black ${card.color}`}>

              {card.value}

            </h2>

          </div>

        ))}

      </div>

      {/* Charts */}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">

        {/* Threat Trend */}

        <div className={`backdrop-blur-xl border rounded-[32px] p-8 shadow-xl ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <h2 className="text-3xl font-black mb-8">

            Threat Trend

          </h2>

          <div className="h-[320px]">

            <ResponsiveContainer width="100%" height="100%">

              <AreaChart data={threatData}>

                <defs>

                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">

                    <stop
                      offset="5%"
                      stopColor="#22D3EE"
                      stopOpacity={0.8}
                    />

                    <stop
                      offset="95%"
                      stopColor="#22D3EE"
                      stopOpacity={0}
                    />

                  </linearGradient>

                </defs>

                <XAxis
                  dataKey="day"
                  stroke="#64748B"
                />

                <Tooltip />

                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke="#22D3EE"
                  strokeWidth={4}
                  fillOpacity={1}
                  fill="url(#colorThreats)"
                />

              </AreaChart>

            </ResponsiveContainer>

          </div>

        </div>

        {/* Attack Sources */}

        <div className={`backdrop-blur-xl border rounded-[32px] p-8 shadow-xl ${
          darkMode

            ? "bg-[#0B1120]/80 border-[#1E293B]"

            : "bg-gray-100 border-gray-200"
        }`}>

          <h2 className="text-3xl font-black mb-8">

            Attack Sources

          </h2>

          <div className="h-[320px]">

            <ResponsiveContainer width="100%" height="100%">

              <BarChart data={attackSources}>

                <XAxis
                  dataKey="country"
                  stroke="#64748B"
                />

                <Tooltip />

                <Bar
                  dataKey="attacks"
                  fill="#22D3EE"
                  radius={[10, 10, 0, 0]}
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