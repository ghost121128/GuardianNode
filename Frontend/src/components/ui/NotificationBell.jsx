import { useState, useEffect } from "react";

import {
  Bell,
  ShieldAlert,
} from "lucide-react";

import { io } from "socket.io-client";

const socket = io("http://127.0.0.1:5000");

const NotificationBell = () => {

  const [open, setOpen] = useState(false);

  const [notifications, setNotifications] =
    useState([]);

  useEffect(() => {

    socket.on(
      "new_threat",
      (newThreat) => {

        const notification = {
          id: Date.now(),
          message: `${newThreat.type} detected`,
          time: "Just now",
        };

        setNotifications((prev) => [
          notification,
          ...prev.slice(0, 5),
        ]);

      }
    );

    return () => {
      socket.off("new_threat");
    };

  }, []);

  return (
    <div className="relative">

      {/* Bell */}
      <button
        onClick={() => setOpen(!open)}
        className="relative bg-[#111827] border border-gray-800 p-3 rounded-2xl hover:border-cyan-500/40 transition-all duration-300"
      >

        <Bell className="text-white" />

        {/* Count */}
        {notifications.length > 0 && (

          <div className="absolute -top-2 -right-2 bg-red-500 text-white text-xs w-6 h-6 rounded-full flex items-center justify-center font-bold">

            {notifications.length}

          </div>

        )}

      </button>

      {/* Dropdown */}
      {open && (

        <div className="absolute right-0 mt-4 w-[350px] bg-[#0B1120] border border-gray-800 rounded-3xl shadow-2xl z-50 overflow-hidden">

          <div className="p-5 border-b border-gray-800">

            <h2 className="text-xl font-bold text-white">
              Notifications
            </h2>

          </div>

          <div className="max-h-[400px] overflow-y-auto">

            {notifications.length === 0 ? (

              <div className="p-6 text-gray-400 text-center">
                No notifications yet
              </div>

            ) : (

              notifications.map((notification) => (

                <div
                  key={notification.id}
                  className="p-5 border-b border-gray-800 hover:bg-[#111827] transition-all duration-300"
                >

                  <div className="flex gap-4">

                    <div className="bg-red-500/10 p-3 rounded-2xl h-fit">

                      <ShieldAlert className="text-red-400" />

                    </div>

                    <div>

                      <p className="font-medium text-white">
                        {notification.message}
                      </p>

                      <p className="text-gray-500 text-sm mt-1">
                        {notification.time}
                      </p>

                    </div>

                  </div>

                </div>

              ))

            )}

          </div>

        </div>

      )}

    </div>
  );
};

export default NotificationBell;