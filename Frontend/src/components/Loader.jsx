import React from "react";

const Loader = () => {

  return (

    <div className="fixed inset-0 bg-[#040816] flex flex-col items-center justify-center z-[9999]">

      <img
        src="/logos/guardiannode-full-logo.svg"
        alt="GuardianNode"
        className="w-28 h-28 animate-pulse"
      />

      <h1 className="text-cyan-400 text-4xl font-black mt-6">

        GuardianNode

      </h1>

      <p className="text-gray-400 mt-3">

        Initializing Cyber Defense Systems...

      </p>

      <div className="w-72 h-2 bg-[#0B1120] rounded-full mt-8 overflow-hidden">

        <div className="h-full bg-cyan-400 animate-pulse w-1/2 rounded-full" />

      </div>

    </div>

  );

};

export default Loader;