import React, {
  useEffect,
  useState,
} from "react";

import {
  Search,
  AlertTriangle,
} from "lucide-react";

import {
  motion,
  AnimatePresence,
} from "framer-motion";

import { io } from "socket.io-client";

// =========================
// Socket Connection
// =========================

const socket = io(
  "https://guardiannode-1.onrender.com",
  {

    transports: [
      "polling",
      "websocket"
    ],

    reconnection: true,

    reconnectionAttempts: 20,

    reconnectionDelay: 1000,

    timeout: 20000,

    forceNew: true,

  }
);

const ThreatFeed = ({
  darkMode,
}) => {

  const [threats, setThreats] =
    useState([]);

  const [search, setSearch] =
    useState("");

  const [filter, setFilter] =
    useState("ALL");

  const [popups, setPopups] =
    useState([]);

  const [selectedThreat, setSelectedThreat] =
    useState(null);

  const isMobile =
    window.innerWidth < 768;

  // =========================
  // Initial Threat Fetch
  // =========================

  const fetchThreats = async () => {

    try {

      const response =
        await fetch(
          "https://guardiannode-1.onrender.com/threats"
        );

      const data =
        await response.json();

      setThreats(
        Array.isArray(data)
          ? data
          : []
      );

    }

    catch (error) {

      console.log(error);

    }

  };

  // =========================
  // Socket.IO Live Events
  // =========================

  useEffect(() => {

    fetchThreats();

    socket.on(
      "connect",
      () => {

        console.log(
          "Socket Connected"
        );

      }
    );

    socket.on(
      "connect_error",
      (err) => {

        console.log(
          "SOCKET ERROR:",
          err
        );

      }
    );

    socket.on(
      "disconnect",
      () => {

        console.log(
          "SOCKET DISCONNECTED"
        );

      }
    );

    socket.on(
      "new_threat",
      (newThreat) => {

        console.log(
          "NEW THREAT RECEIVED",
          newThreat
        );

        // =========================
        // Add Threat Realtime
        // =========================

        setThreats((prev) => [

          {

            ...newThreat,

            timestamp:
              new Date().toLocaleString(),

          },

          ...prev,

        ]);

        // =========================
        // Popup
        // =========================

        const popupId =
          Date.now();

        const popup = {

          ...newThreat,

          id: popupId,

        };

        setPopups((prev) => [

          popup,

          ...prev,

        ]);

        // =========================
        // Auto Remove
        // =========================

        setTimeout(() => {

          setPopups((prev) =>

            prev.filter(
              (p) =>
                p.id !== popupId
            )

          );

        }, 5000);

      }
    );

    return () => {

      socket.off(
        "new_threat"
      );

      socket.off(
        "connect"
      );

      socket.off(
        "connect_error"
      );

      socket.off(
        "disconnect"
      );

    };

  }, []);

  // =========================
  // Filter Logic
  // =========================

  const filteredThreats =
    threats.filter((threat) => {

      const matchesSearch =

        (threat.ip || "")
          .toLowerCase()
          .includes(
            search.toLowerCase()
          )

        ||

        (threat.type || "")
          .toLowerCase()
          .includes(
            search.toLowerCase()
          );

      const matchesFilter =

        filter === "ALL"

        ||

        (threat.severity || "")
          .toUpperCase() ===
        filter.toUpperCase();

      return (
        matchesSearch &&
        matchesFilter
      );

    });

  return (

    <div className={`min-h-screen w-full overflow-x-hidden p-4 md:p-8 pb-28 md:pb-8 transition-colors duration-300 ${
      darkMode
        ? "bg-[#050816] text-white"
        : "bg-gray-100 text-gray-900"
    }`}>

      {/* =========================
          Popup Alerts
      ========================= */}

      <div className="fixed top-4 right-3 sm:right-4 md:right-6 z-[9999] space-y-4 max-w-[90vw]">

        <AnimatePresence>

          {popups.map((popup) => (

            <motion.div

              key={popup.id}

              initial={{
                opacity: 0,
                x: 120,
                scale: 0.9,
              }}

              animate={{
                opacity: 1,
                x: 0,
                scale: 1,
              }}

              exit={{
                opacity: 0,
                x: 120,
                scale: 0.8,
              }}

              transition={{
                duration: 0.3,
              }}

              className={`text-white px-4 md:px-6 py-4 rounded-2xl shadow-2xl border backdrop-blur-xl w-full max-w-[320px] ${
                popup.severity === "Critical"

                  ? "bg-red-500/90 border-red-300"

                  : popup.severity === "High"

                  ? "bg-orange-500/90 border-orange-300"

                  : "bg-cyan-500/90 border-cyan-300"
              }`}
            >

              <div className="flex items-start gap-3">

                <AlertTriangle
                  size={
                    isMobile
                      ? 18
                      : 24
                  }
                  className="mt-1 shrink-0"
                />

                <div className="min-w-0">

                  <h2 className="font-black text-sm md:text-base">

                    Live Threat Detected

                  </h2>

                  <p className="text-xs md:text-sm break-words mt-1">

                    {popup.type}

                  </p>

                  <p className="text-xs opacity-80 mt-2 break-all">

                    {popup.ip}

                  </p>

                  <p className="text-[11px] opacity-70 mt-1">

                    {popup.severity}

                  </p>

                </div>

              </div>

            </motion.div>

          ))}

        </AnimatePresence>

      </div>

      {/* =========================
          Header
      ========================= */}

      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-6 mb-10">

        <div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black mb-3 break-words">

            Threat Feed

          </h1>

          <p className={`text-sm md:text-lg ${
            darkMode
              ? "text-gray-400"
              : "text-gray-500"
          }`}>

            Real-time cyber attack monitoring

          </p>

        </div>

        {/* Live Counter */}

        <div className="bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 px-5 py-4 rounded-2xl font-black text-lg w-fit">

          LIVE THREATS:
          {" "}
          {threats.length}

        </div>

      </div>

    </div>

  );

};

export default ThreatFeed;