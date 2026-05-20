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

import Globe from "../components/Globe";

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

    // Auto Refresh Every 5 Sec

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

      <div className={`min-h-screen flex items-center justify-center transition-all duration-500 ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-gray-100 text-black"
      }`}>

        <h1 className="text-2xl md:text-3xl font-black animate-pulse text-center px-4">

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

      <div className={`min-h-screen flex flex-col items-center justify-center transition-all duration-500 px-4 ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-gray-100 text-black"
      }`}>

        <h1 className="text-2xl md:text-3xl font-black text-red-500 mb-4 text-center">

          Backend Connection Failed

        </h1>

        <p className="text-gray-400 text-center break-all">

          {error}

        </p>

      </div>

    );

  }

  // =========================
  // Dashboard UI
  // =========================

  return (

    <div className={`min-h-screen p-4 md:p-8 transition-all duration-500 ${
      darkMode
        ? "bg-[#040816] text-white"
        : "bg-gray-100 text-gray-900"
    }`}>

      {/* Header */}

      <div className="mb-10">

        <h1 className="text-3xl md:text-6xl font-black mb-4 leading-tight">

          Real-Time{" "}

          <span className="text-cyan-400">

            Cyber Defense

          </span>

        </h1>

        <p className={`text-sm md:text-lg max-w-3xl ${
          darkMode
            ? "text-gray-400"
            : "text-gray-600"
        }`}>

          Monitor live threats, analyze suspicious activity,
          and defend your infrastructure using GuardianNode IDS + IPS architecture.

        </p>

      </div>

      {/* Stats Cards */}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6">

        {/* Total Threats */}

        <div className={`rounded-3xl p-6 shadow-xl border transition-all duration-500 ${
          darkMode
            ? "bg-[#0B1120] border-cyan-500/20 text-white"
            : "bg-white border-gray-200 text-gray-900"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`text-sm md:text-base ${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Total Threats

            </p>

            <ShieldCheck className="text-cyan-400" />

          </div>

          <h1 className="text-3xl md:text-5xl font-black break-words">

            {stats.totalThreats}

          </h1>

        </div>

        {/* Critical Alerts */}

        <div className={`rounded-3xl p-6 shadow-xl border transition-all duration-500 ${
          darkMode
            ? "bg-[#0B1120] border-red-500/20 text-white"
            : "bg-white border-gray-200 text-gray-900"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`text-sm md:text-base ${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Critical Alerts

            </p>

            <AlertTriangle className="text-red-400" />

          </div>

          <h1 className="text-3xl md:text-5xl font-black break-words">

            {stats.criticalAlerts}

          </h1>

        </div>

        {/* Blocked */}

        <div className={`rounded-3xl p-6 shadow-xl border transition-all duration-500 ${
          darkMode
            ? "bg-[#0B1120] border-orange-500/20 text-white"
            : "bg-white border-gray-200 text-gray-900"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`text-sm md:text-base ${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Blocked Attacks

            </p>

            <Ban className="text-orange-400" />

          </div>

          <h1 className="text-3xl md:text-5xl font-black break-words">

            {stats.blockedAttacks}

          </h1>

        </div>

        {/* Monitoring */}

        <div className={`rounded-3xl p-6 shadow-xl border transition-all duration-500 ${
          darkMode
            ? "bg-[#0B1120] border-green-500/20 text-white"
            : "bg-white border-gray-200 text-gray-900"
        }`}>

          <div className="flex justify-between items-center mb-4">

            <p className={`text-sm md:text-base ${
              darkMode
                ? "text-gray-400"
                : "text-gray-500"
            }`}>

              Monitoring

            </p>

            <Activity className="text-green-400" />

          </div>

          <h1 className="text-3xl md:text-5xl font-black break-words">

            {stats.monitoringCount}

          </h1>

        </div>

      </div>

      {/* Globe Section */}

      <div className="mt-10">

        <div className={`rounded-[32px] overflow-hidden shadow-2xl border transition-all duration-500 ${
          darkMode
            ? "bg-[#0B1120] border-cyan-500/10"
            : "bg-white border-gray-200"
        }`}>

          {/* Header */}

          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 px-6 md:px-8 pt-8">

            <h2 className="text-2xl md:text-4xl font-black text-cyan-400">

              Global Cyber Activity

            </h2>

            <div className="bg-cyan-500/10 text-cyan-400 px-5 py-2 rounded-2xl font-bold w-fit">

              LIVE

            </div>

          </div>

          {/* Globe */}

          <div className="mt-6 h-[350px] md:h-[700px] w-full">

            <Globe />

          </div>

        </div>

      </div>

    </div>

  );

};

export default Dashboard;