import { useEffect, useState } from "react";

import {
  motion,
  AnimatePresence,
} from "framer-motion";

import { io } from "socket.io-client";

import {
  ShieldAlert,
  Globe,
  Clock3,
  Activity,
  Search,
  X,
} from "lucide-react";

const socket = io("http://127.0.0.1:5000");

const ThreatFeed = () => {

  const [threats, setThreats] =
    useState([]);

  const [search, setSearch] =
    useState("");

  const [severityFilter, setSeverityFilter] =
    useState("ALL");

  const [selectedThreat, setSelectedThreat] =
    useState(null);

  // Fetch stored threats
  useEffect(() => {

    const fetchThreats = async () => {

      try {

        const response = await fetch(
          "http://127.0.0.1:5000/api/threats"
        );

        const data = await response.json();

        const formattedThreats = data.map(
          (threat, index) => ({
            ...threat,
            id: index + 1,
            status: "Detected",
          })
        );

        setThreats(
          formattedThreats.slice(0, 20)
        );

      } catch (error) {

        console.log(
          "Failed to fetch threats:",
          error
        );

      }

    };

    fetchThreats();

  }, []);

  // Live socket updates
  useEffect(() => {

    socket.on(
      "new_threat",
      (newThreat) => {

        setThreats((prev) => [
          {
            ...newThreat,
            id: Date.now(),
            status: "Detected",
          },
          ...prev.slice(0, 19),
        ]);

      }
    );

    return () => {
      socket.off("new_threat");
    };

  }, []);

  // Filtering
  const filteredThreats = threats.filter(
    (threat) => {

      const matchesSearch =
        threat.ip
          .toLowerCase()
          .includes(search.toLowerCase()) ||

        threat.type
          .toLowerCase()
          .includes(search.toLowerCase());

      const matchesSeverity =
        severityFilter === "ALL" ||
        threat.severity === severityFilter;

      return (
        matchesSearch &&
        matchesSeverity
      );

    }
  );

  const severityStyles = {
    CRITICAL:
      "bg-red-600/20 text-red-400 border border-red-500 shadow-red-500/20",

    HIGH:
      "bg-orange-500/20 text-orange-400 border border-orange-500 shadow-orange-500/20",

    MEDIUM:
      "bg-yellow-500/20 text-yellow-300 border border-yellow-500 shadow-yellow-500/20",
  };

  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="flex items-center justify-between mb-10">

        <div>

          <h1 className="text-5xl font-bold mb-2">
            Threat Feed
          </h1>

          <p className="text-gray-400 text-lg">
            Real-time cyber attack monitoring
          </p>

        </div>

        <div className="flex items-center gap-3 bg-[#0B1120] border border-gray-800 px-5 py-3 rounded-2xl">

          <Activity className="text-green-400 animate-pulse" />

          <span className="text-green-400 font-semibold">
            LIVE
          </span>

        </div>

      </div>

      {/* Filters */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">

        {/* Search */}
        <div className="bg-[#0B1120] border border-gray-800 rounded-2xl px-5 py-4 flex items-center gap-4">

          <Search className="text-gray-400" />

          <input
            type="text"
            placeholder="Search by IP or threat type..."
            value={search}
            onChange={(e) =>
              setSearch(e.target.value)
            }
            className="bg-transparent outline-none w-full text-white"
          />

        </div>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={(e) =>
            setSeverityFilter(e.target.value)
          }
          className="bg-[#0B1120] border border-gray-800 rounded-2xl px-5 py-4 outline-none"
        >

          <option value="ALL">
            All Severities
          </option>

          <option value="CRITICAL">
            Critical
          </option>

          <option value="HIGH">
            High
          </option>

          <option value="MEDIUM">
            Medium
          </option>

        </select>

      </div>

      {/* Threat Feed */}
      <div className="grid gap-6">

        <AnimatePresence>

          {filteredThreats.map((threat) => (

            <motion.div
              key={threat.id}

              onClick={() =>
                setSelectedThreat(threat)
              }

              initial={{
                opacity: 0,
                y: -40,
                scale: 0.95,
              }}

              animate={{
                opacity: 1,
                y: 0,
                scale: 1,
              }}

              exit={{
                opacity: 0,
                scale: 0.9,
              }}

              transition={{
                duration: 0.4,
              }}

              whileHover={{
                scale: 1.02,
              }}

              className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6 shadow-xl hover:border-cyan-500/40 transition-all duration-300 cursor-pointer"
            >

              <div className="flex justify-between items-start mb-6">

                <div className="flex items-center gap-4">

                  <div className="bg-cyan-500/10 p-4 rounded-2xl">

                    <ShieldAlert className="text-cyan-400" />

                  </div>

                  <div>

                    <h2 className="text-2xl font-bold">
                      {threat.type}
                    </h2>

                    <p className="text-gray-400">
                      Suspicious activity detected
                    </p>

                  </div>

                </div>

                <div
                  className={`px-4 py-2 rounded-full text-sm font-bold shadow-lg
                  ${severityStyles[threat.severity]}`}
                >
                  {threat.severity}
                </div>

              </div>

              {/* Threat Info */}
              <div className="grid md:grid-cols-3 gap-4">

                <div className="bg-[#111827] rounded-2xl p-4 border border-gray-800">

                  <div className="flex items-center gap-2 mb-2 text-gray-400">

                    <Globe size={18} />

                    <span>IP Address</span>

                  </div>

                  <p className="text-lg font-semibold">
                    {threat.ip}
                  </p>

                </div>

                <div className="bg-[#111827] rounded-2xl p-4 border border-gray-800">

                  <div className="flex items-center gap-2 mb-2 text-gray-400">

                    <ShieldAlert size={18} />

                    <span>Status</span>

                  </div>

                  <p className="text-lg font-semibold">
                    {threat.status}
                  </p>

                </div>

                <div className="bg-[#111827] rounded-2xl p-4 border border-gray-800">

                  <div className="flex items-center gap-2 mb-2 text-gray-400">

                    <Clock3 size={18} />

                    <span>Detected</span>

                  </div>

                  <p className="text-lg font-semibold">
                    {threat.time}
                  </p>

                </div>

              </div>

            </motion.div>

          ))}

        </AnimatePresence>

      </div>

      {/* Threat Modal */}
      <AnimatePresence>

        {selectedThreat && (

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}

            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-6"
          >

            <motion.div
              initial={{
                scale: 0.8,
                opacity: 0,
              }}

              animate={{
                scale: 1,
                opacity: 1,
              }}

              exit={{
                scale: 0.8,
                opacity: 0,
              }}

              className="bg-[#0B1120] border border-gray-800 rounded-3xl w-full max-w-2xl p-8 relative"
            >

              {/* Close Button */}
              <button
                onClick={() =>
                  setSelectedThreat(null)
                }
                className="absolute top-5 right-5 bg-[#111827] p-2 rounded-xl hover:bg-red-500/20 transition-all"
              >

                <X className="text-white" />

              </button>

              <div className="mb-8">

                <h2 className="text-4xl font-bold mb-3">
                  {selectedThreat.type}
                </h2>

                <p className="text-gray-400">
                  Detailed threat analysis and incident overview.
                </p>

              </div>

              <div className="grid gap-5">

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5">

                  <p className="text-gray-400 mb-2">
                    Source IP
                  </p>

                  <h3 className="text-2xl font-bold">
                    {selectedThreat.ip}
                  </h3>

                </div>

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5">

                  <p className="text-gray-400 mb-2">
                    Severity Level
                  </p>

                  <h3 className="text-2xl font-bold">
                    {selectedThreat.severity}
                  </h3>

                </div>

                <div className="bg-[#111827] border border-gray-800 rounded-2xl p-5">

                  <p className="text-gray-400 mb-2">
                    Recommended Action
                  </p>

                  <p className="text-lg text-gray-300">
                    Immediately investigate suspicious activity,
                    block malicious IP address, and monitor network traffic
                    for further intrusion attempts.
                  </p>

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