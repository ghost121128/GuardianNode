const threats = [
  "SQL Injection detected from Russia",
  "Port scan blocked from Germany",
  "Brute force attack prevented",
  "Suspicious traffic detected",
  "Firewall blocked malicious IP",
];

const ThreatTicker = () => {

  return (

    <div className="overflow-hidden whitespace-nowrap border-y border-cyan-500/20 bg-black/10 backdrop-blur-xl py-3 mb-10">

      <div className="animate-[ticker_25s_linear_infinite] inline-block text-cyan-400 font-semibold text-lg">

        {threats.map((item, index) => (

          <span
            key={index}
            className="mx-10"
          >
            ⚠ {item}
          </span>

        ))}

      </div>

    </div>

  );

};

export default ThreatTicker;