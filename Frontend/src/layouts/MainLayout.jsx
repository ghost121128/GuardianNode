import Sidebar from "../components/ui/Sidebar";
import { Outlet } from "react-router-dom";

const MainLayout = () => {
  return (
    <div className="flex min-h-screen bg-[#050816] text-white">
      
      <Sidebar />

      <div className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </div>

    </div>
  );
};

export default MainLayout;