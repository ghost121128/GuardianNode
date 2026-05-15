import { useEffect, useState } from "react"
import { io } from "socket.io-client"

const socket = io("http://localhost:5000")

export default function ThreatFeed() {
  const [alerts, setAlerts] = useState([
    "SSH Brute Force Attack Detected",
    "Port Scanning Activity Found",
    "Suspicious DNS Request",
    "Unauthorized Login Attempt",
    "Malware Signature Match",
  ])

  useEffect(() => {
    socket.on("new_alert", (data) => {
      setAlerts((prev) => [
        data.message,
        ...prev.slice(0, 5),
      ])
    })

    return () => socket.off("new_alert")
  }, [])

  return (
    <div className="grid lg:grid-cols-3 gap-8 mt-10">
      {/* Threat Feed */}
      <div className="lg:col-span-2 bg-white/5 border border-white/10 backdrop-blur-2xl rounded-3xl p-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-3xl font-black">
              Live Threat Feed
            </h2>

            <p className="text-gray-400 mt-2">
              Real-time intrusion alerts
            </p>
          </div>

          <div className="w-3 h-3 rounded-full bg-red-400 animate-pulse" />
        </div>

        <div className="space-y-4">
          {alerts.map((alert, index) => (
            <div
              key={index}
              className="bg-red-500/10 border border-red-500/20 rounded-2xl p-5 hover:border-red-400/40 transition"
            >
              <div className="flex items-start gap-4">
                <div className="w-3 h-3 rounded-full bg-red-400 mt-2 animate-pulse" />

                <div>
                  <h3 className="font-semibold text-red-300">
                    {alert}
                  </h3>

                  <p className="text-gray-400 text-sm mt-2">
                    Threat Severity: HIGH
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* AI Panel */}
      <div className="bg-white/5 border border-white/10 backdrop-blur-2xl rounded-3xl p-8">
        <h2 className="text-3xl font-black mb-8">
          AI Threat Analysis
        </h2>

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
              Attack Classification
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
        </div>
      </div>
    </div>
  )
}
