import React, {
  useEffect,
  useState,
} from "react";

import {
  Shield,
  AlertTriangle,
  Ban,
  Activity,
} from "lucide-react";

import {
  motion,
} from "framer-motion";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  AreaChart,
  Area,
} from "recharts";

import toast, {
  Toaster,
} from "react-hot-toast";

import {
  io,
} from "socket.io-client";

import Globe from "react-globe.gl";

// =========================
// Socket Connection
// =========================

const socket = io(
  "https://your-render-url.onrender.com"
);

const Dashboard = ({

  darkMode,

}) => {

  // =========================
  // Dashboard Stats
  // =========================

  const [stats, setStats] =
    useState({

      totalThreats: 0,
      criticalAlerts: 0,
      blockedAttacks: 0,
      monitoringCount: 0,

    });

  // =========================
  // Metrics
  // =========================

  const [metrics, setMetrics] =
    useState({

      cpu: 0,
      ram: 0,
      disk: 0,
      uptime: 0,

    });

  // =========================
  // Threats
  // =========================

  const [threats, setThreats] =
    useState([]);

  const isMobile =
    window.innerWidth < 768;

  // =========================
  // Fetch Stats
  // =========================

  const fetchStats = async () => {

    try {

      const response =
        await fetch(
          "https://your-render-url.onrender.com/dashboard-stats"
        );

      const data =
        await response.json();

      setStats(data);

    }

    catch (error) {

      console.log(error);

    }

  };

  // =========================
  // Fetch Metrics
  // =========================

  const fetchMetrics = async () => {

    try {

      const response =
        await fetch(
          "https://your-render-url.onrender.com/system-metrics"
        );

      const data =
        await response.json();

      setMetrics(data);

    }

    catch (error) {

      console.log(error);

    }

  };

  // =========================
  // Fetch Threats
  // =========================

  const fetchThreats = async () => {

    try {

      const response =
        await fetch(
          "https://your-render-url.onrender.com/threats"
        );

      const data =
        await response.json();

      setThreats(data);

    }

    catch (error) {

      console.log(error);

    }

  };

  // =========================
  // Initial Load
  // =========================

  useEffect(() => {

    fetchStats();

    fetchMetrics();

    fetchThreats();

    socket.on(

      "new_threat",

      (
        newThreat
      ) => {

        setThreats(
          (
            prev
          ) => [

            newThreat,
            ...prev,

          ]
        );

        fetchStats();

        if (
          newThreat.severity ===
          "Critical"
        ) {

          toast.error(

            `Critical Threat: ${newThreat.type}`,

            {

              duration: 4000,

            }

          );

        }

      }

    );

    const interval =
      setInterval(() => {

        fetchMetrics();

      }, 5000);

    return () => {

      clearInterval(interval);

      socket.off(
        "new_threat"
      );

    };

  }, []);

  // =========================
  // Cards
  // =========================

  const cards = [

    {

      title:
      "Total Threats",

      value:
      stats.totalThreats,

      icon:
      Shield,

      color:
      "text-cyan-400",

      border:
      "border-cyan-500/20",

    },

    {

      title:
      "Critical Alerts",

      value:
      stats.criticalAlerts,

      icon:
      AlertTriangle,

      color:
      "text-red-400",

      border:
      "border-red-500/20",

    },

    {

      title:
      "Blocked Attacks",

      value:
      stats.blockedAttacks,

      icon:
      Ban,

      color:
      "text-orange-400",

      border:
      "border-orange-500/20",

    },

    {

      title:
      "Monitoring",

      value:
      stats.monitoringCount,

      icon:
      Activity,

      color:
      "text-green-400",

      border:
      "border-green-500/20",

    },

  ];

  // =========================
  // Chart Data
  // =========================

  const severityData = [

    {
      name: "Low",
      value:
      threats.filter(
        (
          t
        ) =>
          t.severity === "Low"
      ).length,
    },

    {
      name: "Medium",
      value:
      threats.filter(
        (
          t
        ) =>
          t.severity === "Medium"
      ).length,
    },

    {
      name: "High",
      value:
      threats.filter(
        (
          t
        ) =>
          t.severity === "High"
      ).length,
    },

    {
      name: "Critical",
      value:
      threats.filter(
        (
          t
        ) =>
          t.severity === "Critical"
      ).length,
    },

  ];

  const COLORS = [

    "#22c55e",
    "#eab308",
    "#f97316",
    "#ef4444",

  ];

  return (

    <div
      className={`min-h-screen relative overflow-hidden transition-all duration-500 ${
        darkMode

          ? "bg-[#030712] text-white"

          : "bg-[#f4f7fb] text-black"
      }`}
    >

      <Toaster position="top-right" />

      {/* Background Glow */}

      <div className="absolute inset-0 overflow-hidden pointer-events-none">

        <div className="absolute w-[400px] h-[400px] bg-cyan-500/10 blur-[90px] rounded-full top-[-150px] left-[-100px]" />

        <div className="absolute w-[400px] h-[400px] bg-blue-500/10 blur-[90px] rounded-full bottom-[-150px] right-[-100px]" />

      </div>

      {/* Navbar */}

      <div className={`relative z-10 flex items-center justify-between px-4 md:px-10 py-6 border-b backdrop-blur-md ${
        darkMode

          ? "border-white/10"

          : "border-black/10"
      }`}>

        <div>

          <h1 className="text-2xl md:text-4xl font-black tracking-tight">

            GuardianNode

          </h1>

          <p className={`text-sm md:text-base ${
            darkMode

              ? "text-gray-400"

              : "text-gray-600"
          }`}>

            Cyber Defense Monitoring System

          </p>

        </div>

      </div>

      {/* Main */}

      <div className="relative z-10 p-4 md:p-10">

        {/* Hero */}

        <motion.div

          initial={{
            opacity: 0,
            y: 20,
          }}

          animate={{
            opacity: 1,
            y: 0,
          }}

          transition={{
            duration: 0.5,
          }}

          className="mb-10"
        >

          <h1 className="text-3xl sm:text-4xl md:text-6xl font-black mb-4 leading-tight">

            Real-Time
            <span className="text-cyan-400">
              {" "}
              Cyber Defense
            </span>

          </h1>

          <p className={`text-sm sm:text-base md:text-lg max-w-3xl ${
            darkMode

              ? "text-gray-400"

              : "text-gray-600"
          }`}>

            Monitor live threats, analyze suspicious activity,
            and defend your infrastructure using GuardianNode IDS + IPS architecture.

          </p>

        </motion.div>

        {/* Stats */}

        <div className="grid grid-cols-2 md:grid-cols-2 xl:grid-cols-4 gap-4 md:gap-6">

          {

            cards.map(
              (
                card,
                index
              ) => {

                const Icon =
                  card.icon;

                return (

                  <motion.div

                    key={index}

                    whileHover={{
                      scale: 1.02,
                    }}

                    className={`${
                      darkMode

                        ? "bg-white/5"

                        : "bg-black/5"
                    } border ${card.border} backdrop-blur-md rounded-[28px] p-4 md:p-7 shadow-xl`}
                  >

                    <div className="flex items-center justify-between mb-4 md:mb-6">

                      <div>

                        <p className={`mb-2 md:mb-3 text-xs md:text-base ${
                          darkMode

                            ? "text-gray-400"

                            : "text-gray-600"
                        }`}>

                          {card.title}

                        </p>

                        <h2 className="text-2xl md:text-5xl font-black">

                          {card.value}

                        </h2>

                      </div>

                      <div className="w-12 h-12 md:w-16 md:h-16 rounded-3xl bg-white/5 flex items-center justify-center">

                        <Icon
                          size={
                            isMobile
                              ? 22
                              : 32
                          }
                          className={card.color}
                        />

                      </div>

                    </div>

                  </motion.div>

                );

              }
            )

          }

        </div>

        {/* Globe */}

        <div className={`mt-10 ${
          darkMode

            ? "bg-white/5"

            : "bg-black/5"
        } border border-cyan-500/20 rounded-[28px] p-4 md:p-7 shadow-xl overflow-hidden`}>

          <div className="flex items-center justify-between mb-6">

            <h2 className="text-xl md:text-3xl font-black text-cyan-400">

              Global Cyber Activity

            </h2>

            <div className="px-3 md:px-4 py-2 rounded-xl bg-cyan-500/10 text-cyan-400 font-bold text-xs md:text-base">

              LIVE

            </div>

          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
            }}

            className="h-[320px] md:h-[700px] w-full rounded-3xl overflow-hidden relative"
          >

            <Globe

              width={
                isMobile
                  ? 320
                  : 1200
              }

              height={
                isMobile
                  ? 320
                  : 700
              }

              globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"

              backgroundColor="rgba(0,0,0,0)"

              pointsData={threats.map(
                (
                  threat
                ) => ({

                  lat:
                  threat.lat,

                  lng:
                  threat.lon,

                  size:
                  threat.severity ===
                  "Critical"

                    ? 0.45

                    : 0.22,

                  color:

                    threat.severity ===
                    "Critical"

                      ? "#ef4444"

                      :

                    threat.severity ===
                    "High"

                      ? "#f97316"

                      :

                    "#06b6d4",

                }))
              }

              pointAltitude={0.015}

              pointRadius="size"

              pointColor="color"

              atmosphereColor="#06b6d4"

              atmosphereAltitude={0.12}

              enablePointerInteraction={true}

              animateIn={true}

            />

          </div>

        </div>

      </div>

    </div>

  );

};

export default Dashboard;