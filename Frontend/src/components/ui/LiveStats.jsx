import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Wifi,
} from "lucide-react";

import {
  useEffect,
  useState,
} from "react";

const LiveStats = () => {

  const [stats, setStats] = useState({

    threats: 332,
    critical: 94,
    traffic: 2.4,
    health: 98,

  });

  useEffect(() => {

    const interval = setInterval(() => {

      console.log(
        "LiveStats running"
      );

      setStats((prev) => ({

        threats:
          prev.threats +
          Math.floor(Math.random() * 3),

        critical:
          prev.critical +
          Math.floor(Math.random() * 2),

        traffic:
          Number(
            (
              prev.traffic +
              Math.random() * 0.2
            ).toFixed(1)
          ),

        health:
          95 +
          Math.floor(Math.random() * 4),

      }));

    }, 4000);

    return () => clearInterval(interval);

  }, []);

  const cards = [

    {
      title: "Threats",
      value: stats.threats,
      icon: <ShieldCheck size={20} />,
      color: "text-cyan-400",
    },

    {
      title: "Critical",
      value: stats.critical,
      icon: <ShieldAlert size={20} />,
      color: "text-red-400",
    },

    {
      title: "Traffic",
      value: `${stats.traffic}TB`,
      icon: <Wifi size={20} />,
      color: "text-orange-400",
    },

    {
      title: "Health",
      value: `${stats.health}%`,
      icon: <Activity size={20} />,
      color: "text-green-400",
    },

  ];

  return (

    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5 mb-8">

      {cards.map((card, index) => (

        <div
          key={index}

          className="bg-gray-100 dark:bg-[#0B1120]/80 backdrop-blur-xl border border-gray-200 dark:border-[#1E293B] rounded-3xl p-6 hover:border-cyan-500/40 transition-all duration-300"
        >

          <div className="flex items-center justify-between mb-6">

            <div className={`p-3 rounded-2xl bg-black/5 dark:bg-black/20 ${card.color}`}>

              {card.icon}

            </div>

          </div>

          <p className="text-gray-500 dark:text-gray-400 text-sm mb-2">

            {card.title}

          </p>

          <h2 className={`text-4xl font-black ${card.color}`}>

            {card.value}

          </h2>

        </div>

      ))}

    </div>

  );

};

export default LiveStats;