import {
  LayoutDashboard,
  ShieldAlert,
  BarChart3,
  Monitor,
  FileText,
  Settings,
} from "lucide-react";

import { Link, useLocation } from "react-router-dom";
import NotificationBell from "./NotificationBell";

const Sidebar = () => {

  const location = useLocation();
  
  <div className="mb-8 flex justify-end">
  <NotificationBell />
</div>

  const menuItems = [
    {
      name: "Dashboard",
      icon: <LayoutDashboard size={20} />,
      path: "/dashboard",
    },
    {
      name: "Threat Feed",
      icon: <ShieldAlert size={20} />,
      path: "/threat-feed",
    },
    {
      name: "Analytics",
      icon: <BarChart3 size={20} />,
      path: "/analytics",
    },
    {
      name: "Monitor",
      icon: <Monitor size={20} />,
      path: "/monitor",
    },
    {
      name: "Reports",
      icon: <FileText size={20} />,
      path: "/reports",
    },
    {
      name: "Settings",
      icon: <Settings size={20} />,
      path: "/settings",
    },
  ];

  return (
    <div className="w-64 h-screen bg-[#0B1120] border-r border-gray-800 p-6 flex flex-col">

      <h1 className="text-3xl font-bold text-white mb-10">
        GuardianNode
      </h1>

      <div className="flex flex-col gap-4">

        {menuItems.map((item, index) => (

          <Link
            key={index}
            to={item.path}
            className={`flex items-center gap-3 p-4 rounded-xl transition-all duration-300
              
              ${
                location.pathname === item.path
                  ? "bg-blue-600 text-white shadow-lg"
                  : "text-gray-400 hover:bg-[#111827] hover:text-white"
              }
            `}
          >

            {item.icon}

            <span className="font-medium">
              {item.name}
            </span>

          </Link>

        ))}

      </div>

    </div>
  );
};

export default Sidebar;