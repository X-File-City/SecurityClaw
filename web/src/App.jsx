import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import StatusPage from './pages/StatusPage.jsx'
import ChatPage from './pages/ChatPage.jsx'
import SkillsPage from './pages/SkillsPage.jsx'
import ConfigPage from './pages/ConfigPage.jsx'
import CronsPage from './pages/CronsPage.jsx'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/status" replace />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="/chat" element={<ChatPage />} />
        <Route path="/chat/:conversationId" element={<ChatPage />} />
        <Route path="/skills" element={<SkillsPage />} />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="/crons" element={<CronsPage />} />
      </Routes>
    </Layout>
  )
}
