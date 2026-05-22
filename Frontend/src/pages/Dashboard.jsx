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
      }
      catch (err) {
        console.error(err);
        setError(err.message);
      }
      finally {
        setLoading(false);
      }
    };
    fetchStats();
    const interval =
      setInterval(fetchStats, 5000);
    return () =>
      clearInterval(interval);
  }, []);
  if (loading) {
    return (
      <div className={`min-h-screen flex items-center justify-center px-4 ${
        darkMode
          ? "bg-[#040816] text-white"
          : "bg-[#F4F7FB] text-black"
      }`}>
        <h1 className="text-2xl sm:text-3xl md:text-4xl font-black animate-pulse text-center">
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
        <h1 className="text-2xl sm:text-3xl md:text-4xl font-black text-red-500 mb-4 text-center">
          Backend Connection Failed
        </h1>
        <p className="text-gray-400 text-center break-words">
          {error}
        </p>
      </div>
    );
  }
  return (
    <div className={`min-h-screen w-full overflow-x-hidden pb-28 md:pb-10 transition-all duration-300 ${
      darkMode
        ? "bg-[#040816] text-white"
        : "bg-[#F4F7FB] text-black"
    }`}>
      <div className="p-4 sm:p-6 md:p-8">
        {/* Heading */}
        <div className="mb-8">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black leading-tight break-words">
            Real-Time Cyber Defense
          </h1>
          <p className={`mt-2 text-sm sm:text-base max-w-4xl leading-relaxed ${
            darkMode
              ? "text-gray-400"
              : "text-gray-600"
          }`}>
            Monitor live threats, analyze suspicious activity, and defend your infrastructure using GuardianNode IDS + IPS architecture.
          </p>
        </div>
        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 2xl:grid-cols-4 gap-5">
          {/* Total Threats */}
          <div className={`rounded-3xl p-5 shadow-xl border transition-all duration-300 ${
            darkMode
              ? "bg-[#0B1120] border-cyan-500/20"
              : "bg-white border-gray-200"
          }`}>
            <div className="flex justify-between items-center mb-4 gap-3">
              <p className={`text-sm md:text-base ${
                darkMode
                  ? "text-gray-400"
                  : "text-gray-500"
              }`}>
                Total Threats
              </p>
              <ShieldCheck className="text-cyan-400 shrink-0" />
            </div>
            <h1 className={`text-4xl sm:text-5xl font-black break-words ${
              darkMode
                ? "text-white"
                : "text-black"
            }`}>
              {stats.totalThreats}
            </h1>
          </div>
          {/* Critical */}
          <div className={`rounded-3xl p-5 shadow-xl border transition-all duration-300 ${
            darkMode
              ? "bg-[#0B1120] border-red-500/20"
              : "bg-white border-gray-200"
          }`}>
            <div className="flex justify-between items-center mb-4 gap-3">
              <p className={`text-sm md:text-base ${
                darkMode
                  ? "text-gray-400"
                  : "text-gray-500"
              }`}>
                Critical Alerts
              </p>
              <AlertTriangle className="text-red-400 shrink-0" />
            </div>
            <h1 className={`text-4xl sm:text-5xl font-black break-words ${
              darkMode
                ? "text-white"
                : "text-black"
            }`}>
              {stats.criticalAlerts}
            </h1>
          </div>
          {/* Blocked */}
          <div className={`rounded-3xl p-5 shadow-xl border transition-all duration-300 ${
            darkMode
              ? "bg-[#0B1120] border-orange-500/20"
              : "bg-white border-gray-200"
          }`}>
            <div className="flex justify-between items-center mb-4 gap-3">
              <p className={`text-sm md:text-base ${
                darkMode
                  ? "text-gray-400"
                  : "text-gray-500"
              }`}>
                Blocked Attacks
              </p>
              <Ban className="text-orange-400 shrink-0" />
            </div>
            <h1 className={`text-4xl sm:text-5xl font-black break-words ${
              darkMode
                ? "text-white"
                : "text-black"
            }`}>
              {stats.blockedAttacks}
            </h1>
          </div>
          {/* Monitoring */}
          <div className={`rounded-3xl p-5 shadow-xl border transition-all duration-300 ${
            darkMode
              ? "bg-[#0B1120] border-green-500/20"
              : "bg-white border-gray-200"
          }`}>
            <div className="flex justify-between items-center mb-4 gap-3">
              <p className={`text-sm md:text-base ${
                darkMode
                  ? "text-gray-400"
                  : "text-gray-500"
              }`}>
                Monitoring
              </p>
              <Activity className="text-green-400 shrink-0" />
            </div>
            <h1 className={`text-4xl sm:text-5xl font-black break-words ${
              darkMode
                ? "text-white"
                : "text-black"
            }`}>
              {stats.monitoringCount}
            </h1>
          </div>
        </div>
        {/* Globe Section */}
        <div className={`mt-8 rounded-[32px] border overflow-hidden shadow-2xl relative transition-all duration-300 ${
          darkMode
            ? "bg-[#020B1D] border-cyan-500/10"
            : "bg-white border-gray-200"
        }`}>
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 px-5 md:px-8 pt-5 md:pt-8">
            <h1 className="text-2xl sm:text-3xl md:text-5xl font-black text-cyan-400 leading-tight break-words">
              Global Cyber Activity
            </h1>
            <div className="bg-cyan-500/10 text-cyan-400 px-4 py-2 rounded-2xl font-bold text-sm md:text-lg w-fit">
              LIVE
            </div>
          </div>
          {/* Globe */}
          <div className="w-full h-[320px] sm:h-[450px] md:h-[600px] lg:h-[700px] flex items-center justify-center overflow-hidden">
            <CyberGlobe />
          </div>
        </div>
      </div>
    </div>
  );
};
export default Dashboard;