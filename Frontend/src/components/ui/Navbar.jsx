import {
  Bell,
  Search,
} from "lucide-react"

export default function Navbar() {
  return (
    <div className="flex items-center justify-between mb-10">
      {/* Search */}
      <div className="w-[420px] bg-white/5 border border-white/10 rounded-2xl px-5 py-4 flex items-center gap-4 backdrop-blur-xl">
        <Search className="w-5 h-5 text-gray-400" />

        <input
          type="text"
          placeholder="Search threats, IPs, reports..."
          className="bg-transparent outline-none text-white w-full placeholder:text-gray-500"
        />
      </div>

      {/* Right Section */}
      <div className="flex items-center gap-5">
        {/* System Status */}
        <div className="px-5 py-3 rounded-2xl bg-green-500/10 border border-green-500/20 text-green-300 text-sm flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-green-400 animate-pulse" />

          System Secure
        </div>

        {/* Notifications */}
        <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center backdrop-blur-xl cursor-pointer hover:border-cyan-500/20 transition">
          <Bell className="w-5 h-5 text-cyan-300" />
        </div>

        {/* Profile */}
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-r from-cyan-400 to-purple-400 flex items-center justify-center font-black text-black text-xl">
          G
        </div>
      </div>
    </div>
  )
}