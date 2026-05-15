export default function StatsCards() {
  const stats = [
    {
      title: "Threats Blocked",
      value: "12,483",
      change: "+12% this week",
      color: "text-cyan-300",
      bg: "bg-cyan-500/10",
      border: "border-cyan-500/20",
    },
    {
      title: "Active Alerts",
      value: "37",
      change: "+5% today",
      color: "text-red-300",
      bg: "bg-red-500/10",
      border: "border-red-500/20",
    },
    {
      title: "Protected Nodes",
      value: "84",
      change: "+8% this month",
      color: "text-green-300",
      bg: "bg-green-500/10",
      border: "border-green-500/20",
    },
    {
      title: "Malicious IPs",
      value: "1,284",
      change: "+21% detected",
      color: "text-purple-300",
      bg: "bg-purple-500/10",
      border: "border-purple-500/20",
    },
  ]

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6 mt-10">
      {stats.map((stat) => (
        <div
          key={stat.title}
          className="bg-white/[0.03] border border-white/10 backdrop-blur-3xl rounded-3xl p-6 shadow-2xl hover:-translate-y-1 hover:shadow-cyan-500/10 hover:border-cyan-500/20 transition-all duration-300"
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-400 text-sm mb-4">
                {stat.title}
              </p>

              <h2
                className={`text-5xl font-black ${stat.color}`}
              >
                {stat.value}
              </h2>

              <div
                className={`mt-5 inline-flex px-3 py-1 rounded-xl text-sm ${stat.bg} ${stat.border} border text-green-300`}
              >
                {stat.change}
              </div>
            </div>

            <div
              className={`w-4 h-4 rounded-full ${stat.bg} border ${stat.border}`}
            />
          </div>
        </div>
      ))}
    </div>
  )
}