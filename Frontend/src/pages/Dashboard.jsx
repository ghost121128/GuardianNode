import React, {
  useEffect,
  useState,
} from "react";

import {
  ShieldCheck,
  AlertTriangle,
  Ban,
  Activity,
} from "lucide-react";

import Globe from "../components/ui/Globe";

const Dashboard = ({ darkMode }) => {

  const [stats, setStats] = useState({

    totalThreats: 0,

    criticalAlerts: 0,

    blockedAttacks: 0,

    monitoringCount: 0,

  });

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  // =========================
  // Fetch Dashboard Stats
  // =========================

  useEffect(() => {

    const fetchStats = async () => {

      try {

        const response = await fetch(
          "https://guardiannode-1.onrender.com/dashboard-stats"
        );

        if (!response.ok) {

          throw new Error(
            "Failed to fetch stats"
          );

        }

        const data =
          await response.json();

        setStats(data);

      } catch (err) {

        console.error(err);

        setError(err.message);

      } finally {

        setLoading(false);

      }

    };

    fetchStats();

    const interval = setInterval(
      fetchStats,
      5000
    );

    return () =>
      clearInterval(interval);

  }, []);

  // =========================
  // Loading State
  // =========================

  if (loading) {

    return (

      <div className={`min-h-screen flex items-center justify-center ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-[#f4f7fb] text-black"
      }`}>

        <h1 className="text-3xl font-black animate-pulse">

          Loading GuardianNode...

        </h1>

      </div>

    );

  }

  // =========================
  // Error State
  // =========================

  if (error) {

    return (

      <div className={`min-h-screen flex flex-col items-center justify-center ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-[#f4f7fb] text-black"
      }`}>

        <h1 className="text-3xl font-black text-red-500 mb-4">

          Backend Connection Failed

        </h1>

        <p className="text-gray-400">

          {error}

        </p>

      </div>

    );

  }

  // =========================
  // Dashboard UI
  // =========================

  return (

    <div className={`min-h-screen p-6 md:p-8 transition-all duration-500 ${
      darkMode
        ? "bg-[#040816] text-white"
        : "bg-[#f4f7fb] text-black"
    }`}>

      {/* ========================= */}
      {/* Header */}
      {/* ========================= */}

      <div className="mb-10">

        <h1 className="text-4xl md:text-6xl font-black leading-tight">

          Real-Time{" "}

          <span className="text-cyan-400">

            Cyber Defense

          </span>

        </h1>

        <p className={`mt-4 text-base md:text-lg max-w-3xl ${
          darkMode
            ? "text-gray-400"
            : "text-gray-600"
        }`}>

          Monitor live threats, analyze suspicious activity,
          and defend your infrastructure using GuardianNode IDS + IPS architecture.

        </p>

      </div>

      {/* ========================= */}
      {/* Stats Cards */}
      {/* ========================= */}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6">

        {/* Total Threats */}

        <div className={`rounded-3xl p-6 border shadow-xl ${
          darkMode
            ? "bg-[#0B1120] border-cyan-500/20"
            : "bg-white border-gray-200"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Total Threats

            </p>

            <ShieldCheck className="text-cyan-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.totalThreats}

          </h1>

        </div>

        {/* Critical Alerts */}

        <div className={`rounded-3xl p-6 border shadow-xl ${
          darkMode
            ? "bg-[#0B1120] border-red-500/20"
            : "bg-white border-gray-200"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Critical Alerts

            </p>

            <AlertTriangle className="text-red-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.criticalAlerts}

          </h1>

        </div>

        {/* Blocked Attacks */}

        <div className={`rounded-3xl p-6 border shadow-xl ${
          darkMode
            ? "bg-[#0B1120] border-orange-500/20"
            : "bg-white border-gray-200"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Blocked Attacks

            </p>

            <Ban className="text-orange-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.blockedAttacks}

          </h1>

        </div>

        {/* Monitoring */}

        <div className={`rounded-3xl p-6 border shadow-xl ${
          darkMode
            ? "bg-[#0B1120] border-green-500/20"
            : "bg-white border-gray-200"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Monitoring

            </p>

            <Activity className="text-green-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.monitoringCount}

          </h1>

        </div>

      </div>

      {/* ========================= */}
      {/* Globe Section */}
      {/* ========================= */}

      <div className="mt-10">

        <div className={`rounded-[32px] overflow-hidden border shadow-2xl ${
          darkMode
            ? "bg-[#081120] border-cyan-500/10"
            : "bg-white border-gray-200"
        }`}>

          {/* Globe Header */}

          <div className="flex items-center justify-between px-6 md:px-8 pt-8">

            <h2 className="text-3xl md:text-5xl font-black text-cyan-400">

              Global Cyber Activity

            </h2>

            <div className="bg-cyan-500/10 text-cyan-400 px-5 py-2 rounded-2xl font-bold">

              LIVE

            </div>

          </div>

          {/* Globe Container */}

          <div className="w-full h-[400px] md:h-[700px] relative">

            <Globe />

          </div>

        </div>

      </div>

    </div>

  );

};

export default Dashboard;