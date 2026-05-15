import {
  LayoutDashboard,
  ShieldAlert,
  BarChart3,
  Activity,
  FileText,
  Settings,
} from "lucide-react"

export default function Sidebar() {
  const items = [
    { title: "Dashboard", icon: LayoutDashboard },
    { title: "Threat Feed", icon: ShieldAlert },
    { title: "Analytics", icon: BarChart3 },
    { title: "Monitor", icon: Activity },
    { title: "Reports", icon: FileText },
    { title: "Settings", icon: Settings },
  ]

  return (
    <aside className="hidden lg:flex w-[180px] min-h-screen bg-[#09111f]/80 border-r border-white/10 backdrop-blur-xl flex-col p-2.5">

      {/* Logo */}
      <div className="mb-6">
        <h1 className="text-[20px] font-black leading-none bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          Guardian Node
        </h1>

        <p className="text-gray-500 text-[9px] mt-1">
          Cyber Defense
        </p>
      </div>

      {/* Navigation */}
      <div className="space-y-1">

        {items.map((item, index) => {
          const Icon = item.icon

          return (
            <div
              key={item.title}
              className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg cursor-pointer transition-all duration-300 ${
                index === 0
                  ? "bg-cyan-500/10 border border-cyan-500/20"
                  : "hover:bg-white/5"
              }`}
            >
              <Icon
                className={`w-4 h-4 ${
                  index === 0
                    ? "text-cyan-300"
                    : "text-gray-400"
                }`}
              />

              <span
                className={`text-[12px] font-medium ${
                  index === 0
                    ? "text-white"
                    : "text-gray-300"
                }`}
              >
                {item.title}
              </span>
            </div>
          )
        })}
      </div>

      {/* Bottom Status */}
      <div className="mt-auto">
        <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-xl p-2.5">

          <div className="flex items-center gap-1.5 mb-2">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />

            <span className="text-[9px] text-green-300">
              Secure
            </span>
          </div>

          <h2 className="text-lg font-black">
            99.9%
          </h2>

          <p className="text-gray-500 text-[9px] mt-1">
            Uptime
          </p>
        </div>
      </div>
    </aside>
  )
}