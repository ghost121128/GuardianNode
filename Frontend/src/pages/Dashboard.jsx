import React, { useEffect, useState } from "react";

import {
  ShieldCheck,
  AlertTriangle,
  Ban,
  Activity,
} from "lucide-react";

import CyberGlobe from "../components/ui/Globe";

const Dashboard = ({ darkMode }) => {

  const [stats, setStats] = useState({
    totalThreats: 0,
    criticalAlerts: 0,
    blockedAttacks: 0,
    monitoringCount: 0,
  });

  const [loading, setLoading] = useState(true);

  const [error, setError] = useState(null);

  useEffect(() => {

    const fetchStats = async () => {

      try {

        const response = await fetch(
          "https://guardiannode-1.onrender.com/dashboard-stats"
        );

        if (!response.ok) {
          throw new Error("Failed to fetch stats");
        }

        const data = await response.json();

        setStats(data);

      } catch (err) {

        console.error(err);

        setError(err.message);

      } finally {

        setLoading(false);

      }

    };

    fetchStats();

    const interval = setInterval(fetchStats, 5000);

    return () => clearInterval(interval);

  }, []);

  if (loading) {

    return (

      <div className={`min-h-screen flex items-center justify-center ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-[#F4F7FB] text-black"
      }`}>

        <h1 className="text-2xl md:text-4xl font-black animate-pulse">

          Loading GuardianNode...

        </h1>

      </div>

    );

  }

  if (error) {

    return (

      <div className={`min-h-screen flex flex-col items-center justify-center p-6 ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-[#F4F7FB] text-black"
      }`}>

        <h1 className="text-2xl md:text-4xl font-black text-red-500 mb-4 text-center">

          Backend Connection Failed

        </h1>

        <p className="text-gray-400 text-center">

          {error}

        </p>

      </div>

    );

  }

  return (

    <div className={`min-h-screen w-full overflow-x-hidden pb-28 md:pb-10 ${
      darkMode
        ? "bg-[#040816] text-white"
        : "bg-[#F4F7FB] text-black"
    }`}>

      <div className="p-4 sm:p-6 md:p-8">

        {/* Heading */}

        <div className="mb-8">

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black leading-tight">

            Real-Time Cyber Defense

          </h1>

          <p className="text-gray-400 mt-2 text-sm sm:text-base">

            Monitor live threats, analyze suspicious activity, and defend your infrastructure using GuardianNode IDS + IPS architecture.

          </p>

        </div>

        {/* Stats */}

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">

          {/* Total Threats */}

          <div className="bg-[#0B1120] rounded-3xl p-5 border border-cyan-500/20 shadow-xl">

            <div className="flex justify-between items-center mb-4">

              <p className="text-gray-400 text-sm md:text-base">

                Total Threats

              </p>

              <ShieldCheck className="text-cyan-400" />

            </div>

            <h1 className="text-5xl font-black">

              {stats.totalThreats}

            </h1>

          </div>

          {/* Critical */}

          <div className="bg-[#0B1120] rounded-3xl p-5 border border-red-500/20 shadow-xl">

            <div className="flex justify-between items-center mb-4">

              <p className="text-gray-400 text-sm md:text-base">

                Critical Alerts

              </p>

              <AlertTriangle className="text-red-400" />

            </div>

            <h1 className="text-5xl font-black">

              {stats.criticalAlerts}

            </h1>

          </div>

          {/* Blocked */}

          <div className="bg-[#0B1120] rounded-3xl p-5 border border-orange-500/20 shadow-xl">

            <div className="flex justify-between items-center mb-4">

              <p className="text-gray-400 text-sm md:text-base">

                Blocked Attacks

              </p>

              <Ban className="text-orange-400" />

            </div>

            <h1 className="text-5xl font-black">

              {stats.blockedAttacks}

            </h1>

          </div>

          {/* Monitoring */}

          <div className="bg-[#0B1120] rounded-3xl p-5 border border-green-500/20 shadow-xl">

            <div className="flex justify-between items-center mb-4">

              <p className="text-gray-400 text-sm md:text-base">

                Monitoring

              </p>

              <Activity className="text-green-400" />

            </div>

            <h1 className="text-5xl font-black">

              {stats.monitoringCount}

            </h1>

          </div>

        </div>

       {/* Globe Section */}

<div className="mt-8 bg-[#020B1D] rounded-[32px] border border-cyan-500/10 overflow-hidden shadow-2xl relative">

  <div className="flex items-center justify-between px-5 md:px-8 pt-5 md:pt-8">

    <h1 className="text-3xl md:text-5xl font-black text-cyan-400 leading-tight">

      Global Cyber Activity

    </h1>

    <div className="bg-cyan-500/10 text-cyan-400 px-4 py-2 rounded-2xl font-bold text-sm md:text-lg">

      LIVE

    </div>

  </div>

  <div className="w-full h-[500px] md:h-[700px] flex items-center justify-center overflow-hidden">

   <CyberGlobe />

  </div>

</div>

</div>

        </div>

    

  );

};

export default Dashboard;