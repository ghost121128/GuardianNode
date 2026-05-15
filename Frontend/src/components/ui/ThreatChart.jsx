import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts"

const data = [
  { time: "10:00", attacks: 12 },
  { time: "11:00", attacks: 19 },
  { time: "12:00", attacks: 8 },
  { time: "13:00", attacks: 24 },
  { time: "14:00", attacks: 15 },
  { time: "15:00", attacks: 29 },
]

export default function ThreatChart() {
  return (
    <div className="bg-white/[0.03] border border-white/10 backdrop-blur-3xl rounded-3xl p-8 shadow-2xl hover:-translate-y-1 hover:shadow-cyan-500/10 transition-all duration-300">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-3xl font-black">
            Threat Analytics
          </h2>

          <p className="text-gray-400 mt-2">
            Real-time cyber attack monitoring
          </p>
        </div>

        <div className="px-4 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-sm">
          LIVE
        </div>
      </div>

      <div className="h-[220px] xl:h-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <XAxis
              dataKey="time"
              stroke="#888"
              tick={{ fill: "#9CA3AF" }}
            />

            <YAxis
              stroke="#888"
              tick={{ fill: "#9CA3AF" }}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "#0B1026",
                border: "1px solid rgba(255,255,255,0.1)",
                borderRadius: "16px",
                color: "#fff",
              }}
            />

            <Line
              type="monotone"
              dataKey="attacks"
              stroke="#00FFFF"
              strokeWidth={4}
              dot={{
                r: 6,
                fill: "#00FFFF",
              }}
              activeDot={{
                r: 8,
              }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}