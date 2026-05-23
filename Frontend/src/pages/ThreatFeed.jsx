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
      "websocket",
    ],

    reconnection: true,

    reconnectionAttempts: 20,

    reconnectionDelay: 1000,

    timeout: 20000,

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
  // Realtime Threat System
  // =========================

  useEffect(() => {

    // =========================
    // Initial Threat Load
    // =========================

    const loadThreats =
      async () => {

        try {

          const response =
            await fetch(
              "https://guardiannode-1.onrender.com/threats"
            );

          const data =
            await response.json();

          if (
            Array.isArray(data)
          ) {

            setThreats(
              data.slice(0, 20)
            );

          }

        }

        catch (error) {

          console.log(error);

        }

      };

    loadThreats();

    // =========================
    // Socket Connected
    // =========================

    socket.on(
      "connect",
      () => {

        console.log(
          "SOCKET CONNECTED"
        );

      }
    );

    // =========================
    // Live Threat Event
    // =========================

    socket.on(
      "new_threat",
      (newThreat) => {

        console.log(
          "LIVE THREAT:",
          newThreat
        );

        const threatData = {

          ...newThreat,

          timestamp:
            new Date().toLocaleString(),

        };

        // =========================
        // Add Threat Instantly
        // =========================

        setThreats((prev) => {

          const exists =
            prev.some(
              (t) =>

                t.ip ===
                threatData.ip

                &&

                t.type ===
                threatData.type

            );

          if (exists) {

            return prev;

          }

          return [

            threatData,

            ...prev.slice(0, 49),

          ];

        });

        // =========================
        // Popup Alert
        // =========================

        const popupId =
          Date.now();

        const popup = {

          ...threatData,

          id: popupId,

        };

        setPopups((prev) => [

          popup,

          ...prev.slice(0, 2),

        ]);

        // =========================
        // Remove Popup
        // =========================

        setTimeout(() => {

          setPopups((prev) =>

            prev.filter(
              (p) =>
                p.id !== popupId
            )

          );

        }, 4000);

      }
    );

    // =========================
    // Cleanup
    // =========================

    return () => {

      socket.off(
        "connect"
      );

      socket.off(
        "new_threat"
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

      {/* =========================
          Search + Filter
      ========================= */}

      <div className="flex flex-col sm:flex-row gap-4 w-full mb-8">

        {/* Search */}

        <div className={`border rounded-2xl px-4 md:px-5 py-3 flex items-center gap-3 shadow-lg w-full min-w-0 ${
          darkMode
            ? "bg-[#0B1120] border-[#1E293B]"
            : "bg-white border-gray-200"
        }`}>

          <Search
            className="text-gray-400 shrink-0"
            size={18}
          />

          <input
            type="text"
            placeholder="Search threats..."
            value={search}
            onChange={(e) =>
              setSearch(
                e.target.value
              )
            }
            className="bg-transparent outline-none w-full text-sm md:text-base"
          />

        </div>

        {/* Filter */}

        <select

          value={filter}

          onChange={(e) =>
            setFilter(
              e.target.value
            )
          }

          className={`rounded-2xl px-4 md:px-5 py-3 shadow-lg border text-sm md:text-base w-full sm:w-[180px] ${
            darkMode
              ? "bg-[#0B1120] border-[#1E293B] text-white"
              : "bg-white border-gray-200 text-black"
          }`}
        >

          <option value="ALL">
            All
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

          <option value="CRITICAL">
            Critical
          </option>

          <option value="LOW">
            Low
          </option>

        </select>

      </div>

      {/* =========================
          Threat Cards
      ========================= */}

      <div className="space-y-5">

        {

          filteredThreats.length > 0 ? (

            filteredThreats
              .slice(0, 20)
              .map(
                (
                  threat,
                  index
                ) => (

                  <motion.div

                    key={index}

                    initial={{
                      opacity: 0,
                      y: 15,
                    }}

                    animate={{
                      opacity: 1,
                      y: 0,
                    }}

                    transition={{
                      duration: 0.2,
                    }}

                    onClick={() =>
                      setSelectedThreat(threat)
                    }

                    className={`cursor-pointer border rounded-[28px] p-4 md:p-6 shadow-xl hover:shadow-2xl transition-all duration-300 ${
                      darkMode
                        ? "bg-[#0B1120]/80 border-[#1E293B]"
                        : "bg-white border-gray-200"
                    }`}
                  >

                    <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-4 mb-6">

                      <div>

                        <h2 className="text-2xl sm:text-3xl font-black mb-2 break-words">

                          {threat.type}

                        </h2>

                        <p className={`text-sm md:text-base ${
                          darkMode
                            ? "text-gray-400"
                            : "text-gray-500"
                        }`}>

                          Real-time suspicious activity detected

                        </p>

                      </div>

                      <div className="bg-orange-500/10 text-orange-500 px-4 md:px-5 py-2 rounded-full font-bold w-fit text-sm md:text-base">

                        {threat.severity}

                      </div>

                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-5">

                      <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-4 md:p-5`}>

                        <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2 text-sm`}>

                          IP Address

                        </p>

                        <h3 className="text-base md:text-xl font-bold break-all">

                          {threat.ip}

                        </h3>

                      </div>

                      <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-4 md:p-5`}>

                        <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2 text-sm`}>

                          Status

                        </p>

                        <h3 className="text-base md:text-xl font-bold text-green-500 break-words">

                          {threat.status}

                        </h3>

                      </div>

                      <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-4 md:p-5`}>

                        <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2 text-sm`}>

                          Timestamp

                        </p>

                        <h3 className="text-xs md:text-sm font-bold break-all">

                          {threat.timestamp}

                        </h3>

                      </div>

                    </div>

                  </motion.div>

                )
              )

          ) : (

            <div className={`rounded-[28px] p-8 md:p-10 text-center border ${
              darkMode
                ? "bg-[#0B1120] border-[#1E293B]"
                : "bg-white border-gray-200"
            }`}>

              <h1 className="text-2xl md:text-4xl font-black mb-4">

                No Threats Found

              </h1>

              <p className="text-gray-400">

                GuardianNode is monitoring infrastructure.

              </p>

            </div>

          )

        }

      </div>

      {/* =========================
          Modal Popup
      ========================= */}

      <AnimatePresence>

        {selectedThreat && (

          <motion.div

            initial={{
              opacity: 0,
            }}

            animate={{
              opacity: 1,
            }}

            exit={{
              opacity: 0,
            }}

            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          >

            <motion.div

              initial={{
                scale: 0.9,
                y: 40,
              }}

              animate={{
                scale: 1,
                y: 0,
              }}

              exit={{
                scale: 0.9,
                y: 40,
              }}

              className={`w-full max-w-2xl rounded-[32px] p-6 md:p-8 border shadow-2xl relative ${
                darkMode
                  ? "bg-[#0B1120] border-[#1E293B]"
                  : "bg-white border-gray-200"
              }`}
            >

              <button

                onClick={() =>
                  setSelectedThreat(null)
                }

                className="absolute top-4 right-4 bg-red-500 text-white w-10 h-10 rounded-full font-black"
              >

                X

              </button>

              <h1 className="text-3xl md:text-5xl font-black mb-4 pr-10 break-words">

                {selectedThreat.type}

              </h1>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                <div className="bg-black/10 rounded-2xl p-4">

                  <p className="text-gray-400 text-sm mb-2">

                    IP Address

                  </p>

                  <h2 className="font-black break-all">

                    {selectedThreat.ip}

                  </h2>

                </div>

                <div className="bg-black/10 rounded-2xl p-4">

                  <p className="text-gray-400 text-sm mb-2">

                    Severity

                  </p>

                  <h2 className="font-black text-orange-500">

                    {selectedThreat.severity}

                  </h2>

                </div>

                <div className="bg-black/10 rounded-2xl p-4">

                  <p className="text-gray-400 text-sm mb-2">

                    Status

                  </p>

                  <h2 className="font-black text-green-500">

                    {selectedThreat.status}

                  </h2>

                </div>

                <div className="bg-black/10 rounded-2xl p-4">

                  <p className="text-gray-400 text-sm mb-2">

                    Timestamp

                  </p>

                  <h2 className="font-black break-all text-sm">

                    {selectedThreat.timestamp}

                  </h2>

                </div>

              </div>

            </motion.div>

          </motion.div>

        )}

      </AnimatePresence>

    </div>

  );

};

export default ThreatFeed;