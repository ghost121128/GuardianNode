import {
  FileText,
  ShieldCheck,
  Download,
  CalendarDays,
  AlertTriangle,
} from "lucide-react";

const reports = [
  {
    id: 1,
    title: "Weekly Threat Report",
    date: "15 May 2026",
    threats: 128,
    status: "Generated",
  },
  {
    id: 2,
    title: "Network Activity Report",
    date: "14 May 2026",
    threats: 87,
    status: "Generated",
  },
  {
    id: 3,
    title: "Security Audit Summary",
    date: "13 May 2026",
    threats: 42,
    status: "Generated",
  },
];

const Reports = () => {

  // Download CSV Report
  const downloadCSV = async () => {

    try {

      const response = await fetch(
        "http://127.0.0.1:5000/api/export/csv"
      );

      const blob = await response.blob();

      const url =
        window.URL.createObjectURL(blob);

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        "threat_report.csv";

      document.body.appendChild(link);

      link.click();

      link.remove();

    } catch (error) {

      console.log(
        "Download failed:",
        error
      );

    }

  };

  return (
    <div className="min-h-screen bg-[#050816] text-white p-8">

      {/* Header */}
      <div className="mb-10">

        <h1 className="text-5xl font-bold mb-2">
          Security Reports
        </h1>

        <p className="text-gray-400 text-lg">
          Threat intelligence and security audit reports
        </p>

      </div>

      {/* Top Stats */}
      <div className="grid md:grid-cols-3 gap-6 mb-10">

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-4">

            <ShieldCheck className="text-green-400" />

            <p className="text-gray-400">
              Security Score
            </p>

          </div>

          <h2 className="text-5xl font-bold text-green-400">
            92%
          </h2>

        </div>

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-4">

            <AlertTriangle className="text-red-400" />

            <p className="text-gray-400">
              Critical Threats
            </p>

          </div>

          <h2 className="text-5xl font-bold text-red-400">
            18
          </h2>

        </div>

        <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

          <div className="flex items-center gap-3 mb-4">

            <FileText className="text-cyan-400" />

            <p className="text-gray-400">
              Reports Generated
            </p>

          </div>

          <h2 className="text-5xl font-bold text-cyan-400">
            64
          </h2>

        </div>

      </div>

      {/* Reports List */}
      <div className="bg-[#0B1120] border border-gray-800 rounded-3xl p-6">

        <div className="flex items-center justify-between mb-8">

          <h2 className="text-3xl font-bold">
            Recent Reports
          </h2>

          {/* Generate Report Button */}
          <button
            onClick={downloadCSV}
            className="bg-cyan-500 hover:bg-cyan-400 transition-all duration-300 px-5 py-3 rounded-2xl font-semibold text-black"
          >
            Generate CSV Report
          </button>

        </div>

        <div className="space-y-5">

          {reports.map((report) => (

            <div
              key={report.id}
              className="bg-[#111827] border border-gray-800 rounded-2xl p-5 hover:border-cyan-500/40 transition-all duration-300"
            >

              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">

                <div>

                  <h3 className="text-2xl font-semibold mb-2">
                    {report.title}
                  </h3>

                  <div className="flex flex-wrap gap-6 text-gray-400">

                    <div className="flex items-center gap-2">

                      <CalendarDays size={18} />

                      <span>{report.date}</span>

                    </div>

                    <div className="flex items-center gap-2">

                      <AlertTriangle size={18} />

                      <span>
                        {report.threats} Threats
                      </span>

                    </div>

                  </div>

                </div>

                {/* Download Button */}
                <button
                  onClick={downloadCSV}
                  className="bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500 px-4 py-3 rounded-2xl transition-all duration-300 flex items-center justify-center"
                >

                  <Download className="text-cyan-400" />

                </button>

              </div>

            </div>

          ))}

        </div>

      </div>

    </div>
  );
};

export default Reports;