import { motion } from "framer-motion"

import Sidebar from "../components/ui/Sidebar"
import Navbar from "../components/ui/Navbar"
import StatsCards from "../components/ui/StatsCards"
import ThreatChart from "../components/ui/ThreatChart"
import ThreatFeed from "../components/ui/ThreatFeed"
import AttackMap from "../components/ui/AttackMap"
import AIInsights from "../components/ui/AIInsights"
import ParticlesBackground from "../components/ui/ParticlesBackground"

export default function Dashboard() {

  const user = JSON.parse(
    localStorage.getItem("user")
  )

  return (
    <div className="relative min-h-screen bg-gradient-to-br from-[#050816] via-[#0B1026] to-[#14052C] text-white flex overflow-hidden">

      {/* Particles */}
      <ParticlesBackground />

      {/* Background Blobs */}
      <div className="absolute top-0 left-0 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[120px]" />

      <div className="absolute bottom-0 right-0 w-[500px] h-[500px] bg-purple-500/10 rounded-full blur-[120px]" />

      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <main className="relative z-10 flex-1 overflow-y-auto p-6 lg:p-10">

        <Navbar />

        {/* Heading */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="mt-8"
        >
          <h1 className="text-4xl md:text-5xl xl:text-6xl font-black leading-tight">
            Welcome, {user?.name}
          </h1>

          <p className="text-gray-400 mt-4 text-base md:text-lg max-w-3xl">
            Real-time intrusion detection and cyber threat monitoring platform.
          </p>
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <StatsCards />
        </motion.div>

        {/* Analytics */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="grid grid-cols-1 xl:grid-cols-12 gap-8 mt-8"
        >
          <div className="xl:col-span-8">
            <ThreatChart />
          </div>

          <div className="xl:col-span-4">
            <AIInsights />
          </div>
        </motion.div>

        {/* Threat Feed */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
        >
          <ThreatFeed />
        </motion.div>

        {/* Attack Map */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <AttackMap />
        </motion.div>

      </main>
    </div>
  )
}