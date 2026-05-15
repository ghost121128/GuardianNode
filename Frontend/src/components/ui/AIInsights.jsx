export default function AIInsights() {
  return (
    <div className="bg-white/[0.03] border border-white/10 backdrop-blur-3xl rounded-3xl p-6 shadow-2xl hover:-translate-y-1 hover:shadow-purple-500/10 transition-all duration-300 h-full">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-black">
            AI Insights
          </h2>

          <p className="text-gray-400 mt-2 text-sm">
            Threat intelligence engine
          </p>
        </div>

        <div className="w-3 h-3 rounded-full bg-cyan-400 animate-pulse" />
      </div>

      <div className="space-y-6">
        <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-2xl p-5">
          <p className="text-gray-400 text-sm mb-2">
            Threat Confidence
          </p>

          <h3 className="text-5xl font-black text-cyan-300">
            94%
          </h3>
        </div>

        <div className="bg-purple-500/10 border border-purple-500/20 rounded-2xl p-5">
          <p className="text-gray-400 text-sm mb-2">
            Attack Pattern
          </p>

          <h3 className="text-2xl font-black text-purple-300">
            PORT SCAN
          </h3>
        </div>

        <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-5">
          <p className="text-gray-400 text-sm mb-2">
            Recommended Action
          </p>

          <h3 className="text-xl font-black text-green-300">
            BLOCK SOURCE IP
          </h3>
        </div>

        <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-5">
          <p className="text-gray-400 text-sm mb-2">
            Active Critical Threats
          </p>

          <h3 className="text-5xl font-black text-red-300">
            12
          </h3>
        </div>
      </div>
    </div>
  )
}