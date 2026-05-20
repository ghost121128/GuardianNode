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

  // =========================
  // Fetch Threats
  // =========================

  const fetchThreats = async () => {

    try {

      const response =
        await fetch(
          "http://127.0.0.1:5000/threats"
        );

      const data =
        await response.json();

      setThreats(data);

      // =========================
      // Optimized Popup Alerts
      // =========================

      if (data.length > 0) {

        const latestThreat =
          data[0];

        const popupId =
          Date.now();

        const newPopup = {

          ...latestThreat,

          id: popupId,

        };

        setPopups((prev) => [

          newPopup,

          ...prev.slice(0, 1),

        ]);

        setTimeout(() => {

          setPopups((prev) =>

            prev.filter(
              (p) =>
                p.id !== popupId
            )

          );

        }, 3500);

      }

    }

    catch (error) {

      console.log(error);

    }

  };

  useEffect(() => {

    fetchThreats();

    const interval =
      setInterval(
        fetchThreats,
        5000
      );

    return () =>
      clearInterval(interval);

  }, []);

  // =========================
  // Filter Logic
  // =========================

  const filteredThreats =
    threats.filter((threat) => {

      const matchesSearch =

        threat.ip
          .toLowerCase()
          .includes(
            search.toLowerCase()
          )

        ||

        threat.type
          .toLowerCase()
          .includes(
            search.toLowerCase()
          );

      const matchesFilter =

        filter === "ALL"

        ||

        threat.severity === filter;

      return (
        matchesSearch &&
        matchesFilter
      );

    });

  return (

    <div className={`min-h-screen p-8 transition-colors duration-300 ${
      darkMode

        ? "bg-[#050816] text-white"

        : "bg-gray-100 text-gray-900"
    }`}>

      {/* ========================= */}
      {/* Popup Alerts */}
      {/* ========================= */}

      <div className="fixed top-6 right-6 z-50 space-y-4">

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

            className="bg-red-500 text-white px-6 py-4 rounded-2xl shadow-2xl"
          >

            <div className="flex items-center gap-3">

              <AlertTriangle />

              <div>

                <h2 className="font-black">

                  Threat Detected

                </h2>

                <p className="text-sm">

                  {popup.type}

                </p>

              </div>

            </div>

          </motion.div>

        ))}

      </div>

      {/* ========================= */}
      {/* Header */}
      {/* ========================= */}

      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6 mb-10">

        <div>

          <h1 className="text-5xl font-black mb-3">

            Threat Feed

          </h1>

          <p className={`text-lg ${
            darkMode

              ? "text-gray-400"

              : "text-gray-500"
          }`}>

            Real-time cyber attack monitoring

          </p>

        </div>

        {/* Search + Filter */}

        <div className="flex gap-4 flex-wrap">

          {/* Search */}

          <div className={`border rounded-2xl px-5 py-3 flex items-center gap-3 shadow-lg ${
            darkMode

              ? "bg-[#0B1120] border-[#1E293B]"

              : "bg-white border-gray-200"
          }`}>

            <Search
              className="text-gray-400"
              size={20}
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

              className="bg-transparent outline-none"
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

            className={`rounded-2xl px-5 py-3 shadow-lg border ${
              darkMode

                ? "bg-[#0B1120] border-[#1E293B] text-white"

                : "bg-white border-gray-200 text-black"
            }`}
          >

            <option value="ALL">

              All

            </option>

            <option value="High">

              High

            </option>

            <option value="Medium">

              Medium

            </option>

            <option value="Critical">

              Critical

            </option>

            <option value="Low">

              Low

            </option>

          </select>

        </div>

      </div>

      {/* ========================= */}
      {/* Threat Cards */}
      {/* ========================= */}

      <div className="space-y-5">

        {

          filteredThreats
            .slice(0, 15)
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

                  className={`cursor-pointer border rounded-[28px] p-6 shadow-xl hover:shadow-2xl transition-all duration-300 ${
                    darkMode

                      ? "bg-[#0B1120]/80 border-[#1E293B]"

                      : "bg-white border-gray-200"
                  }`}
                >

                  {/* Top */}

                  <div className="flex justify-between items-center mb-6">

                    <div>

                      <h2 className="text-3xl font-black mb-2">

                        {threat.type}

                      </h2>

                      <p className={`${
                        darkMode

                          ? "text-gray-400"

                          : "text-gray-500"
                      }`}>

                        Suspicious activity detected

                      </p>

                    </div>

                    <div className="bg-orange-500/10 text-orange-500 px-5 py-2 rounded-full font-bold">

                      {threat.severity}

                    </div>

                  </div>

                  {/* Grid */}

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-5">

                    {/* IP */}

                    <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-5`}>

                      <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                        IP Address

                      </p>

                      <h3 className="text-xl font-bold">

                        {threat.ip}

                      </h3>

                    </div>
                                        {/* Status */}

                    <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-5`}>

                      <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                        Status

                      </p>

                      <h3 className="text-xl font-bold text-green-500">

                        {threat.status}

                      </h3>

                    </div>

                    {/* Timestamp */}

                    <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-2xl p-5`}>

                      <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                        Timestamp

                      </p>

                      <h3 className="text-sm font-bold break-all">

                        {threat.timestamp}

                      </h3>

                    </div>

                  </div>

                </motion.div>

              )
            )

        }

      </div>

      {/* ========================= */}
      {/* Optimized Modal */}
      {/* ========================= */}

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

            transition={{
              duration: 0.2,
            }}

            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-6"
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

              transition={{
                duration: 0.2,
              }}

              className={`border p-8 w-full max-w-3xl rounded-[32px] shadow-2xl relative overflow-hidden ${
                darkMode

                  ? "bg-[#0B1120] border-[#1E293B]"

                  : "bg-white border-gray-200"
              }`}
            >

              {/* Close */}

              <button

                onClick={() =>
                  setSelectedThreat(null)
                }

                className="absolute top-5 right-5 bg-red-500 text-white w-10 h-10 rounded-full font-black"
              >

                X

              </button>

              {/* Header */}

              <div className="mb-8">

                <h1 className="text-5xl font-black mb-3">

                  {selectedThreat.type}

                </h1>

                <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} text-lg`}>

                  Full threat intelligence report

                </p>

              </div>

              {/* Info */}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-3xl p-6`}>

                  <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                    IP Address

                  </p>

                  <h2 className="text-2xl font-black">

                    {selectedThreat.ip}

                  </h2>

                </div>

                <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-3xl p-6`}>

                  <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                    Severity

                  </p>

                  <h2 className="text-2xl font-black text-orange-500">

                    {selectedThreat.severity}

                  </h2>

                </div>

                <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-3xl p-6`}>

                  <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                    Status

                  </p>

                  <h2 className="text-2xl font-black text-green-500">

                    {selectedThreat.status}

                  </h2>

                </div>

                <div className={`${darkMode ? "bg-[#111827]" : "bg-gray-100"} rounded-3xl p-6`}>

                  <p className={`${darkMode ? "text-gray-400" : "text-gray-500"} mb-2`}>

                    Timestamp

                  </p>

                  <h2 className="text-lg font-black break-all">

                    {selectedThreat.timestamp}

                  </h2>

                </div>

              </div>

              {/* Analysis */}

              <div className="mt-8 bg-red-500/10 border border-red-500/20 rounded-3xl p-6">

                <h2 className="text-2xl font-black mb-4 text-red-500">

                  Threat Analysis

                </h2>

                <p className={`${darkMode ? "text-gray-300" : "text-gray-700"} leading-relaxed`}>

                  GuardianNode detected suspicious
                  network activity matching
                  behavioral patterns of
                  {` ${selectedThreat.type} `}
                  attacks.

                  The system classified this
                  threat as
                  {` ${selectedThreat.severity} `}
                  severity and automatically
                  triggered defensive monitoring
                  protocols.

                </p>

              </div>

            </motion.div>

          </motion.div>

        )}

      </AnimatePresence>

    </div>

  );

};

export default ThreatFeed;