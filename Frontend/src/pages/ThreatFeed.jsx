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
const socket = io(
  "https://guardiannode-1.onrender.com"
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
      "new_threat",
      (newThreat) => {
        // Add realtime threat
        setThreats((prev) => [
          {
            ...newThreat,
            timestamp:
              new Date().toLocaleString(),
          },
          ...prev,
        ]);
        // Popup Alert
        const popupId =
          Date.now();
        const popup = {
          ...newThreat,
          id: popupId,
        };
        setPopups((prev) => [
          popup,
          ...prev.slice(0, 1),
        ]);
        // Auto remove popup
        setTimeout(() => {
          setPopups((prev) =>
            prev.filter(
              (p) =>
                p.id !== popupId
            )
          );
        }, 3500);
      }
    );
    return () => {
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
      {/* Popup Alerts */}
      <div className="fixed top-4 right-3 sm:right-4 md:right-6 z-50 space-y-4 max-w-[90vw]">
        {popups.map((popup) => (
          <motion.div
            key={popup.id}
            initial={{
              opacity: 0,
              x: 80,
            }}
            animate={{
              opacity: 1,
              x: 0,
            }}
            exit={{
              opacity: 0,
              x: 80,
            }}
            transition={{
              duration: 0.25,
            }}
            className={`text-white px-4 md:px-6 py-3 md:py-4 rounded-2xl shadow-2xl w-full max-w-[280px] sm:max-w-sm ${
              popup.severity ===
              "Critical"
                ? "bg-red-500"
                : popup.severity ===
                  "High"
                ? "bg-orange-500"
                : "bg-cyan-500"
            }`}
          >
            <div className="flex items-center gap-3">
              <AlertTriangle
                size={
                  isMobile
                    ? 18
                    : 24
                }
              />
              <div>
                <h2 className="font-black text-sm md:text-base">
                  Live Threat Detected
                </h2>
                <p className="text-xs md:text-sm break-words">
                  {popup.type}
                </p>
                <p className="text-xs opacity-80 mt-1">
                  {popup.ip}
                </p>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
      {/* Header */}
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
      {/* Search + Filter */}
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
      {/* Threat Cards */}
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
            </div>
          )
        }
      </div>
    </div>
  );
};
export default ThreatFeed;