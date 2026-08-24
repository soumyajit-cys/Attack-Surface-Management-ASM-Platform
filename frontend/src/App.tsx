import { Router } from './router'
import { ToastProvider } from './components/ui/Toaster'

export default function App() {
  return (
    <ToastProvider>
      <Router />
    </ToastProvider>
  )
}