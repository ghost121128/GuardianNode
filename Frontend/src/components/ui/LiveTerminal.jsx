import {
  useEffect,
  useState,
} from "react";

const LiveTerminal = () => {

  const [logs, setLogs] = useState([]);

  useEffect(() => {

    const interval = setInterval(async () => {

      try {

        const response = await fetch(
          "https://your-render-url.onrender.com/api/live-logs"
        );

        const data = await response.json();

        setLogs((prev) => {

          const updated = [
            data.log,
            ...prev,
          ];

          return updated.slice(0, 8);

        });

      }

      catch (error) {

        console.log(error);

      }

    }, 2500);

    return () => clearInterval(interval);

  }, []);

  return (

    <div className="bg-gray-100 dark:bg-black border border-gray-200 dark:border-cyan-500/20 rounded-[32px] p-6 shadow-2xl h-[350px] overflow-hidden transition-all duration-500">

      {/* Header */}
      <div className="flex items-center justify-between mb-6">

        <div>

          <h2 className="text-2xl font-black text-cyan-400 mb-1">
            Live Security Terminal
          </h2>

          <p className="text-gray-500 dark:text-gray-400 text-sm">
            Real-time GuardianNode monitoring logs
          </p>

        </div>

        <div className="flex items-center gap-2">

          <div className="w-3 h-3 rounded-full bg-green-400 animate-pulse" />

          <span className="text-green-400 text-sm font-bold">
            ACTIVE
          </span>

        </div>

      </div>

      {/* Logs */}
      <div className="space-y-3 overflow-y-auto h-[240px] pr-2">

        {logs.map((log, index) => (

          <div
            key={index}

            className="bg-white dark:bg-[#07111F] border border-gray-200 dark:border-cyan-500/10 rounded-2xl px-4 py-3 text-sm font-mono text-gray-800 dark:text-cyan-300 transition-all duration-500"
          >

            {log}

          </div>

        ))}

      </div>

    </div>

  );

};

export default LiveTerminal;