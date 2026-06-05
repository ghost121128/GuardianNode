import React from "react";

import {
  Shield,
  Activity,
  Globe,
  Lock,
  ArrowRight,
} from "lucide-react";

import {
  Link,
} from "react-router-dom";

const Home = () => {

  return (

    <div className="min-h-screen bg-[#040816] text-white overflow-x-hidden">

      {/* =========================
          Navbar
      ========================= */}

      <nav className="w-full flex items-center justify-between px-6 md:px-12 py-6 border-b border-white/10">

        <div className="flex items-center gap-4">

          <img
            src="/logos/guardiannode-full-logo.svg"
            alt="GuardianNode"
            className="w-[180px] object-contain"
          />

        </div>

        <Link
          to="/login"
          className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold px-6 py-3 rounded-2xl transition-all duration-300"
        >

          Launch Dashboard

        </Link>

      </nav>

      {/* =========================
          Hero Section
      ========================= */}

      <section className="relative w-full px-6 md:px-12 py-24 md:py-32">

        <div className="max-w-6xl mx-auto grid grid-cols-1 xl:grid-cols-2 gap-20 items-center">

          {/* Left */}

          <div>

            <div className="inline-flex items-center gap-3 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 px-5 py-3 rounded-full mb-8">

              <Shield size={18} />

              Next Generation Cyber Defense

            </div>

            <h1 className="text-5xl md:text-7xl font-black leading-tight mb-8">

              Real-Time

              <span className="text-cyan-400">

                {" "}
                Threat Intelligence

              </span>

              {" "}Platform

            </h1>

            <p className="text-gray-400 text-lg md:text-xl leading-relaxed mb-10 max-w-2xl">

              GuardianNode is a modern cybersecurity
              monitoring platform providing realtime
              threat detection, intrusion monitoring,
              attack visualization, analytics,
              and intelligent security insights.

            </p>

            <div className="flex flex-col sm:flex-row gap-5">

              <Link
                to="/login"
                className="bg-cyan-500 hover:bg-cyan-400 text-black font-black px-8 py-4 rounded-2xl transition-all duration-300 flex items-center justify-center gap-3"
              >

                Launch Dashboard

                <ArrowRight size={20} />

              </Link>

              <a
                href="https://github.com"
                target="_blank"
                rel="noreferrer"
                className="border border-white/10 hover:border-cyan-500/30 hover:bg-cyan-500/10 px-8 py-4 rounded-2xl transition-all duration-300 font-bold text-center"
              >

                View Source

              </a>

            </div>

          </div>

          {/* Right */}

          <div className="relative">

            <div className="absolute inset-0 bg-cyan-500/20 blur-[120px]" />

            <img
              src="/dashboard-preview.png"
              alt="GuardianNode Dashboard"
              className="relative rounded-[32px] border border-white/10 shadow-2xl"
            />

          </div>

        </div>

      </section>

      {/* =========================
          Features
      ========================= */}

      <section className="px-6 md:px-12 py-24">

        <div className="max-w-7xl mx-auto">

          <div className="text-center mb-20">

            <h1 className="text-5xl font-black mb-6">

              Enterprise Security Features

            </h1>

            <p className="text-gray-400 text-xl">

              Advanced cybersecurity tools built for realtime monitoring

            </p>

          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-8">

            {[
              {
                icon: Shield,
                title: "Threat Detection",
                desc: "Realtime intrusion monitoring and malicious traffic analysis.",
              },

              {
                icon: Activity,
                title: "Live Analytics",
                desc: "Monitor security metrics and attack activity instantly.",
              },

              {
                icon: Globe,
                title: "Global Attack Map",
                desc: "Visualize cyber attacks and IP locations worldwide.",
              },

              {
                icon: Lock,
                title: "IPS Protection",
                desc: "Automatic blocking and intelligent defense systems.",
              },

            ].map((feature, index) => {

              const Icon =
                feature.icon;

              return (

                <div
                  key={index}
                  className="bg-[#0B1120]/80 border border-[#1E293B] rounded-[32px] p-8 hover:border-cyan-500/30 transition-all duration-300"
                >

                  <div className="bg-cyan-500/10 w-16 h-16 rounded-2xl flex items-center justify-center mb-8">

                    <Icon
                      className="text-cyan-400"
                      size={30}
                    />

                  </div>

                  <h2 className="text-2xl font-black mb-4">

                    {feature.title}

                  </h2>

                  <p className="text-gray-400 leading-relaxed">

                    {feature.desc}

                  </p>

                </div>

              );

            })}

          </div>

        </div>

      </section>

      {/* =========================
          Stats
      ========================= */}

      <section className="px-6 md:px-12 py-20">

        <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6">

          {[
            {
              number: "99.9%",
              label: "Threat Accuracy",
            },

            {
              number: "24/7",
              label: "Realtime Monitoring",
            },

            {
              number: "500+",
              label: "Threat Logs",
            },

            {
              number: "50+",
              label: "Blocked Attacks",
            },

          ].map((stat, index) => (

            <div
              key={index}
              className="bg-[#0B1120]/80 border border-[#1E293B] rounded-[28px] p-8 text-center"
            >

              <h1 className="text-4xl md:text-5xl font-black text-cyan-400 mb-4">

                {stat.number}

              </h1>

              <p className="text-gray-400">

                {stat.label}

              </p>

            </div>

          ))}

        </div>

      </section>

      {/* =========================
          Footer
      ========================= */}

      <footer className="border-t border-white/10 py-10 px-6 md:px-12 mt-20">

        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">

          <div>

            <img
              src="/logos/guardiannode-full-logo.svg"
              alt="GuardianNode"
              className="w-[180px]"
            />

            <p className="text-gray-500 mt-4">

              Advanced Cyber Defense Platform

            </p>

          </div>

          <p className="text-gray-500 text-center">

            © 2026 GuardianNode. All rights reserved.

          </p>

        </div>

      </footer>

    </div>

  );

};

export default Home;