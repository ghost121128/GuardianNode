import {
  FileText,
  Download,
  ShieldCheck,
  Calendar,
} from "lucide-react";

const reports = [
  {
    id: 1,
    title: "Weekly Threat Report",
    date: "17 May 2026",
    threats: 124,
  },

  {
    id: 2,
    title: "Network Security Audit",
    date: "15 May 2026",
    threats: 82,
  },

  {
    id: 3,
    title: "Critical Incident Summary",
    date: "12 May 2026",
    threats: 34,
  },
];

const Reports = ({

  darkMode,

}) => {

  const isMobile =
    window.innerWidth < 768;

  const downloadReport = () => {

    const reportContent = `

GuardianNode Security Report
============================

Generated: ${new Date().toLocaleString()}

Total Threats Blocked: 332
Critical Alerts: 94
System Health: 98%

Recent Incidents:
- SQL Injection blocked
- DDoS traffic detected
- Malware signature detected
- Firewall blocked malicious IP

GuardianNode Enterprise Security Suite
`;

    const blob = new Blob(
      [reportContent],
      {
        type: "text/plain",
      }
    );

    const url =
      window.URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;

    link.download =
      "GuardianNode_Report.txt";

    document.body.appendChild(link);

    link.click();

    link.remove();

    window.URL.revokeObjectURL(url);

  };

  return (

    <div className={`min-h-screen p-4 md:p-8 transition-all duration-500 ${
      darkMode

        ? "bg-[#040816] text-white"

        : "bg-white text-gray-900"
    }`}>

      {/* Header */}

      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-6 mb-10">

        <div>

          <h1 className="text-3xl md:text-5xl font-black mb-2">

            Reports

          </h1>

          <p className={`text-sm md:text-base ${
            darkMode

              ? "text-gray-400"

              : "text-gray-500"
          }`}>

            Security reports and incident documentation

          </p>

        </div>

        <button
          onClick={downloadReport}

          className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold px-4 md:px-6 py-3 rounded-2xl transition-all duration-300 flex items-center justify-center gap-3 w-full sm:w-fit text-sm md:text-base"
        >

          <Download
            size={
              isMobile
                ? 16
                : 18
            }
          />

          Export Report

        </button>

      </div>

      {/* Top Cards */}

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 md:gap-6 mb-10">

        {[
          {
            title: "Generated Reports",
            value: "38",
          },

          {
            title: "Threat Logs",
            value: "2,431",
          },

          {
            title: "Resolved Incidents",
            value: "192",
          },
        ].map((card, index) => (

          <div
            key={index}

            className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-4 md:p-6 shadow-xl ${
              darkMode

                ? "bg-[#0B1120]/80 border-[#1E293B]"

                : "bg-gray-100 border-gray-200"
            }`}
          >

            <div className="flex items-center justify-between mb-4 md:mb-5">

              <div className="bg-cyan-500/10 p-3 md:p-4 rounded-2xl">

                <ShieldCheck
                  className="text-cyan-400"
                  size={
                    isMobile
                      ? 20
                      : 24
                  }
                />

              </div>

            </div>

            <p className={`text-xs md:text-sm mb-2 ${
              darkMode

                ? "text-gray-400"

                : "text-gray-500"
            }`}>

              {card.title}

            </p>

            <h2 className="text-2xl md:text-4xl font-black text-cyan-400">

              {card.value}

            </h2>

          </div>

        ))}

      </div>

      {/* Reports List */}

      <div className="space-y-5 md:space-y-6">

        {reports.map((report) => (

          <div
            key={report.id}

            className={`backdrop-blur-xl border rounded-[28px] md:rounded-[32px] p-4 md:p-7 shadow-xl hover:border-cyan-500/40 transition-all duration-300 ${
              darkMode

                ? "bg-[#0B1120]/80 border-[#1E293B]"

                : "bg-gray-100 border-gray-200"
            }`}
          >

            <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-6">

              {/* Left */}

              <div className="flex items-start gap-4 md:gap-5">

                <div className="bg-cyan-500/10 p-3 md:p-4 rounded-2xl">

                  <FileText
                    className="text-cyan-400"
                    size={
                      isMobile
                        ? 20
                        : 24
                    }
                  />

                </div>

                <div>

                  <h2 className="text-lg md:text-2xl font-black mb-3">

                    {report.title}

                  </h2>

                  <div className={`flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-5 text-sm md:text-base ${
                    darkMode

                      ? "text-gray-400"

                      : "text-gray-500"
                  }`}>

                    <div className="flex items-center gap-2">

                      <Calendar
                        size={
                          isMobile
                            ? 14
                            : 16
                        }
                      />

                      {report.date}

                    </div>

                    <div>

                      {report.threats} Threats Logged

                    </div>

                  </div>

                </div>

              </div>

              {/* Right */}

              <button
                onClick={downloadReport}

                className="bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 px-4 md:px-5 py-3 rounded-2xl transition-all duration-300 flex items-center justify-center gap-3 text-sm md:text-base w-full sm:w-fit"
              >

                <Download
                  size={
                    isMobile
                      ? 16
                      : 18
                  }
                />

                Download

              </button>

            </div>

          </div>

        ))}

      </div>

    </div>

  );

};

export default Reports;