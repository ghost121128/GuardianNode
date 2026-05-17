import { useEffect, useState } from "react";

import { motion } from "framer-motion";

import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  ShieldCheck,
  Globe,
  Bell,
} from "lucide-react";

const Dashboard = () => {

  const [stats, setStats] = useState({
    total_threats: 0,
    critical_threats: 0,
    high_threats: 0,
    medium_threats: 0,
  });

  useEffect(() => {

    const fetchStats = async () => {

      try {

        const response = await fetch(
          "http://127.0.0.1:5000/api/stats"
        );

        const data = await response.json();

        setStats(data);

      } catch (error) {

        console.log(
          "Failed to fetch stats:",
          error
        );

      }

    };

    fetchStats();

    const interval = setInterval(
      fetchStats,
      5000
    );

    return () => clearInterval(interval);

  }, []);

  const cards = [
    {
      title: "Total Threats",
      value: stats.total_threats,
      icon: <ShieldAlert size={28} />,
      color: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
    {
      title: "Critical Threats",
      value: stats.critical_threats,
      icon: <AlertTriangle size={28} />,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      title: "High Severity",
      value: stats.high_threats,
      icon: <Activity size={28} />,
      color: "text-orange-400",
      bg: "bg-orange-500/10",
    },
    {
      title: "Medium Severity",
      value: stats.medium_threats,
      icon: <ShieldCheck size={28} />,
      color: "text-yellow-400",
      bg: "bg-yellow-500/10",
    },
  ];

  return (
    <div className="min-h-screen bg-[#050816] text-white p-8 overflow-hidden relative">

      {/* Background Glow */}
      <div className="absolute top-0 left-0 w-[400px] h-[400px] bg-cyan-500/10 blur-[120px] rounded-full" />

      <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-purple-500/10 blur-[120px] rounded-full" />

      {/* Header */}
      <div className="relative z-10 flex justify-between items-center mb-12">

        <div>

          <h1 className="text-6xl font-black mb-3">
            Welcome, Kalpesh
          </h1>

          <p className="text-gray-400 text-xl">
            Real-time intrusion detection and cyber threat monitoring platform.
          </p>

        </div>

        {/* Right Header */}
        <div className="flex items-center gap-4">

          <div className="bg-green-500/10 border border-green-500/30 px-5 py-3 rounded-2xl flex items-center gap-3 min-w-[190px] justify-center">

            <Globe
              size={22}
              className="text-green-400"
            />

            <span className="font-semibold text-green-400">
              System Secure
            </span>

          </div>

          <div className="bg-[#111827] border border-gray-800 p-4 rounded-2xl">

            <Bell className="text-white" />

          </div>

        </div>

      </div>

      {/* Stats Cards */}
      <div className="relative z-10 grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">

        {cards.map((card, index) => (

          <motion.div
            key={index}

            initial={{
              opacity: 0,
              y: 40,
            }}

            animate={{
              opacity: 1,
              y: 0,
            }}

            transition={{
              delay: index * 0.1,
            }}

            whileHover={{
              scale: 1.03,
            }}

            className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6 hover:border-cyan-500/30 transition-all duration-300 shadow-xl"
          >

            <div
              className={`${card.bg} w-fit p-4 rounded-2xl mb-5`}
            >

              <div className={card.color}>
                {card.icon}
              </div>

            </div>

            <p className="text-gray-400 mb-3 text-lg">
              {card.title}
            </p>

            <h2
              className={`text-5xl font-black ${card.color}`}
            >
              {card.value}
            </h2>

          </motion.div>

        ))}

      </div>

      {/* Lower Widgets */}
      <div className="relative z-10 grid lg:grid-cols-2 gap-8">

        {/* Threat Analytics */}
        <motion.div
          initial={{
            opacity: 0,
            x: -30,
          }}

          animate={{
            opacity: 1,
            x: 0,
          }}

          className="bg-[#0B1120] border border-gray-800 rounded-3xl p-8"
        >

          <div className="flex justify-between items-center mb-8">

            <div>

              <h2 className="text-4xl font-black mb-2">
                Threat Analytics
              </h2>

              <p className="text-gray-400">
                Real-time cyber attack monitoring
              </p>

            </div>

            <div className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-4 py-2 rounded-2xl font-semibold">
              LIVE
            </div>

          </div>

          {/* Fake Graph */}
          <div className="flex items-end gap-4 h-[220px]">

            {[60, 120, 90, 180, 140, 200, 170].map(
              (height, index) => (

                <motion.div
                  key={index}

                  initial={{
                    height: 0,
                  }}

                  animate={{
                    height,
                  }}

                  transition={{
                    duration: 1,
                    delay: index * 0.1,
                  }}

                  className="flex-1 bg-gradient-to-t from-cyan-500 to-blue-500 rounded-t-2xl"
                />

              )
            )}

          </div>

        </motion.div>

        {/* AI Insights */}
        <motion.div
          initial={{
            opacity: 0,
            x: 30,
          }}

          animate={{
            opacity: 1,
            x: 0,
          }}

          className="bg-[#0B1120] border border-gray-800 rounded-3xl p-8"
        >

          <div className="flex justify-between items-center mb-8">

            <div>

              <h2 className="text-4xl font-black mb-2">
                AI Insights
              </h2>

              <p className="text-gray-400">
                Threat intelligence engine
              </p>

            </div>

            <div className="w-4 h-4 bg-cyan-400 rounded-full animate-pulse" />

          </div>

          <div className="space-y-5">

            {[
              "Critical increase in port scanning activity",
              "Multiple suspicious IPs detected globally",
              "Brute force attempts rising rapidly",
              "AI predicts elevated attack probability",
            ].map((item, index) => (

              <motion.div
                key={index}

                initial={{
                  opacity: 0,
                  y: 20,
                }}

                animate={{
                  opacity: 1,
                  y: 0,
                }}

                transition={{
                  delay: index * 0.2,
                }}

                className="bg-[#111827] border border-gray-800 rounded-2xl p-5"
              >

                <div className="flex gap-4">

                  <div className="bg-cyan-500/10 p-3 rounded-2xl h-fit">

                    <ShieldAlert className="text-cyan-400" />

                  </div>

                  <p className="text-lg text-gray-300">
                    {item}
                  </p>

                </div>

              </motion.div>

            ))}

          </div>

        </motion.div>

      </div>

    </div>
  );
};

export default Dashboard;