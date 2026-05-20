import { useEffect, useState } from "react";

import {
  motion,
  AnimatePresence,
} from "framer-motion";

import { io } from "socket.io-client";

import {
  Wifi,
  ShieldAlert,
  Activity,
  Globe,
} from "lucide-react";

const socket = io(
  "https://your-render-url.onrender.com"
);

const PacketMonitor = () => {

  const [packets, setPackets] =
    useState([]);

  useEffect(() => {

    socket.on(
      "live_packet",
      (packet) => {

        if (!packet) return;

        setPackets((prev) => [

          {
            id: Date.now(),
            ...packet,
          },

          ...prev.slice(0, 14),

        ]);

      }
    );

    return () => {

      socket.off(
        "live_packet"
      );

    };

  }, []);

  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="flex justify-between items-center mb-10">

        <div>

          <h1 className="text-5xl font-bold mb-2">
            Packet Monitor
          </h1>

          <p className="text-gray-400 text-lg">
            Real-time network packet inspection
          </p>

        </div>

        <div className="flex items-center gap-3 bg-[#0B1120] border border-gray-800 px-5 py-3 rounded-2xl">

          <Activity className="text-green-400 animate-pulse" />

          <span className="text-green-400 font-semibold">
            LIVE TRAFFIC
          </span>

        </div>

      </div>

      {/* Packet List */}
      <div className="grid gap-5">

        <AnimatePresence>

          {packets.map((packet) => (

            <motion.div
              key={packet.id}

              initial={{
                opacity: 0,
                y: -40,
              }}

              animate={{
                opacity: 1,
                y: 0,
              }}

              exit={{
                opacity: 0,
              }}

              transition={{
                duration: 0.4,
              }}

              className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6 hover:border-cyan-500/30 transition-all duration-300"
            >

              <div className="flex justify-between items-start mb-6">

                <div className="flex items-center gap-4">

                  <div className="bg-cyan-500/10 p-4 rounded-2xl">

                    <Wifi className="text-cyan-400" />

                  </div>

                  <div>

                    <h2 className="text-2xl font-bold">
                      {packet.type}
                    </h2>

                    <p className="text-gray-400">
                      Real network packet captured
                    </p>

                  </div>

                </div>

                <div
                  className={`px-4 py-2 rounded-full text-sm font-bold
                  ${
                    packet.status ===
                    "Suspicious"
                      ? "bg-red-500/20 text-red-400 border border-red-500"
                      : "bg-green-500/20 text-green-400 border border-green-500"
                  }`}
                >
                  {packet.status}
                </div>

              </div>

              {/* Packet Details */}
              <div className="grid md:grid-cols-3 gap-4">

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-4">

                  <div className="flex items-center gap-2 text-gray-400 mb-2">

                    <Globe size={18} />

                    <span>Source IP</span>

                  </div>

                  <p className="text-lg font-semibold break-all">
                    {packet.sourceIP}
                  </p>

                </div>

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-4">

                  <div className="flex items-center gap-2 text-gray-400 mb-2">

                    <ShieldAlert size={18} />

                    <span>Destination</span>

                  </div>

                  <p className="text-lg font-semibold break-all">
                    {packet.destinationIP}
                  </p>

                </div>

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-4">

                  <div className="flex items-center gap-2 text-gray-400 mb-2">

                    <Activity size={18} />

                    <span>Status</span>

                  </div>

                  <p className="text-lg font-semibold">
                    {packet.status}
                  </p>

                </div>

              </div>

            </motion.div>

          ))}

        </AnimatePresence>

      </div>

    </div>
  );
};

export default PacketMonitor;