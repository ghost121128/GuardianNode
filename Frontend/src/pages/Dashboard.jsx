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

        console.log(
          "Dashboard API:",
          data
        );

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

      <div className={`min-h-screen flex items-center justify-center ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-white text-black"
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
          : "bg-white text-black"
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

    <div className={`min-h-screen p-8 ${
      darkMode
        ? "bg-[#040816] text-white"
        : "bg-white text-black"
    }`}>

      <h1 className="text-5xl font-black mb-10">

        Real-Time Cyber Defense

      </h1>

      {/* Stats Cards */}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">

        {/* Total Threats */}

        <div className="bg-[#0B1120] border border-cyan-500/20 rounded-3xl p-6">

          <div className="flex justify-between items-center mb-4">

            <p className="text-gray-400">

              Total Threats

            </p>

            <ShieldCheck className="text-cyan-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.totalThreats}

          </h1>

        </div>

        {/* Critical Alerts */}

        <div className="bg-[#0B1120] border border-red-500/20 rounded-3xl p-6">

          <div className="flex justify-between items-center mb-4">

            <p className="text-gray-400">

              Critical Alerts

            </p>

            <AlertTriangle className="text-red-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.criticalAlerts}

          </h1>

        </div>

        {/* Blocked */}

        <div className="bg-[#0B1120] border border-orange-500/20 rounded-3xl p-6">

          <div className="flex justify-between items-center mb-4">

            <p className="text-gray-400">

              Blocked Attacks

            </p>

            <Ban className="text-orange-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.blockedAttacks}

          </h1>

        </div>

        {/* Monitoring */}

        <div className="bg-[#0B1120] border border-green-500/20 rounded-3xl p-6">

          <div className="flex justify-between items-center mb-4">

            <p className="text-gray-400">

              Monitoring

            </p>

            <Activity className="text-green-400" />

          </div>

          <h1 className="text-5xl font-black">

            {stats.monitoringCount}

          </h1>

        </div>

      </div>

    </div>

  );

};

export default Dashboard;