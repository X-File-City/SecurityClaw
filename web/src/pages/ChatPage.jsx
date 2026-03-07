import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Plus, Send, Trash2 } from 'lucide-react'
import { api, streamChat } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'

function upsertConversationItem(items, nextItem) {
  const index = items.findIndex((item) => item.id === nextItem.id)
  if (index === -1) {
    return [nextItem, ...items]
  }

  const copy = [...items]
  copy[index] = { ...copy[index], ...nextItem }
  return copy
}

function StepChip({ step }) {
  const cls = {
    thinking: 'badge-cyan',
    fetching: 'badge-amber',
    evaluating: 'badge-green',
    processing: 'badge-dim',
  }[step.kind] || 'badge-dim'
  return <span className={`badge ${cls}`}>{step.label}</span>
}

export default function ChatPage() {
  const { conversationId } = useParams()
  const navigate = useNavigate()
  const [conversations, setConversations] = useState([])
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [steps, setSteps] = useState([])
  const [busy, setBusy] = useState(false)
  const activeId = conversationId || null
  
  const messagesEndRef = useRef(null)
  const stepsEndRef = useRef(null)
  const streamingConversationIdRef = useRef(null)
  const isStreamingRef = useRef(false)

  const scrollToMessagesBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const scrollToStepsBottom = () => {
    stepsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => { scrollToMessagesBottom() }, [messages])
  useEffect(() => { scrollToStepsBottom() }, [steps])

  const loadConversations = async () => {
    const res = await api.get('/api/conversations')
    setConversations(res.data.items || [])
  }

  const loadConversation = async (id) => {
    if (!id) {
      setMessages([])
      return
    }
    const res = await api.get(`/api/conversations/${id}`)
    setMessages(res.data.messages || [])
  }

  useEffect(() => { loadConversations() }, [])
  useEffect(() => {
    if (!activeId) {
      setMessages([])
      return
    }
    // Skip reloading if this conversation is currently receiving a stream
    if (isStreamingRef.current && streamingConversationIdRef.current === activeId) {
      return
    }
    loadConversation(activeId)
  }, [activeId])

  const newChat = () => {
    setMessages([])
    setSteps([])
    navigate('/chat')
  }

  const removeConversation = async (id) => {
    await api.delete(`/api/conversations/${id}`)
    await loadConversations()
    if (activeId === id) navigate('/chat')
  }

  const send = async () => {
    if (!input.trim() || busy) return
    const outgoing = input.trim()
    const userTimestamp = new Date().toISOString()
    const userMessage = {
      role: 'user',
      content: outgoing,
      timestamp: userTimestamp,
    }
    setMessages((prev) => [...prev, userMessage])
    isStreamingRef.current = true
    setBusy(true)
    setSteps([])
    setInput('')

    if (activeId) {
      setConversations((prev) => upsertConversationItem(prev, {
        id: activeId,
        first_question: prev.find((item) => item.id === activeId)?.first_question || outgoing,
        preview: outgoing,
        messages: messages.length + 1,
        timestamp: userTimestamp,
        last_update: userTimestamp,
      }))
    }

    try {
      await streamChat({
        message: outgoing,
        conversationId: activeId,
        onEvent: async (event, payload) => {
          if (event === 'meta' && payload.conversation_id && !activeId) {
            streamingConversationIdRef.current = payload.conversation_id
            setConversations((prev) => upsertConversationItem(prev, {
              id: payload.conversation_id,
              first_question: outgoing,
              preview: outgoing,
              messages: 1,
              timestamp: userTimestamp,
              last_update: userTimestamp,
              created_at: userTimestamp,
            }))
            navigate(`/chat/${payload.conversation_id}`, { replace: true })
          }
          if (event === 'step') {
            setSteps((prev) => [...prev, payload])
          }
          if (event === 'response') {
            const responseTimestamp = new Date().toISOString()
            const resolvedConversationId = payload.conversation_id || activeId || streamingConversationIdRef.current
            setMessages((prev) => [...prev, {
              role: 'assistant',
              content: payload.response,
              timestamp: responseTimestamp,
              routing_skills: payload.routing?.skills || [],
            }])
            if (resolvedConversationId) {
              setConversations((prev) => upsertConversationItem(prev, {
                id: resolvedConversationId,
                first_question: prev.find((item) => item.id === resolvedConversationId)?.first_question || outgoing,
                preview: outgoing,
                messages: Math.max(prev.find((item) => item.id === resolvedConversationId)?.messages || 0, 2),
                timestamp: responseTimestamp,
                last_update: responseTimestamp,
              }))
            }
            await loadConversations()
          }
        },
      })
    } finally {
      isStreamingRef.current = false
      streamingConversationIdRef.current = null
      setBusy(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  const orderedConversations = useMemo(() => {
    return [...conversations].sort((a, b) => {
      const timeA = new Date(a.timestamp || a.created_at || 0).getTime()
      const timeB = new Date(b.timestamp || b.created_at || 0).getTime()
      return timeB - timeA
    })
  }, [conversations])

  return (
    <div className="flex h-full min-h-0 gap-6">
      <div className="panel flex w-80 flex-col overflow-hidden">
        <div className="border-b border-border p-4">
          <button className="btn btn-primary w-full" onClick={newChat}>
            <Plus className="h-4 w-4" /> New Chat
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-3 space-y-2">
          {orderedConversations.map((conv) => (
            <div key={conv.id} className={`rounded-xl border p-3 ${activeId === conv.id ? 'border-cyan bg-cyan/10' : 'border-border bg-panel2'}`}>
              <button className="w-full text-left" onClick={() => navigate(`/chat/${conv.id}`)}>
                <div className="truncate font-mono text-xs uppercase tracking-[0.14em] text-cyan">{conv.id}</div>
                <div className="mt-1 line-clamp-2 text-sm text-text">{conv.first_question || conv.preview || 'Conversation'}</div>
                <div className="mt-2 font-mono text-[11px] text-dim">{conv.messages} entries</div>
              </button>
              <button className="mt-3 inline-flex items-center gap-1 text-xs text-danger" onClick={() => removeConversation(conv.id)}>
                <Trash2 className="h-3 w-3" /> delete
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-col gap-6">
        <PageHeader title="Chat" subtitle="Supervisor-driven operator console with step-level progress, not raw logs." />

        <div className="grid min-h-0 flex-1 gap-6 xl:grid-cols-[2fr_1fr]">
          <div className="panel flex min-h-0 flex-col overflow-hidden">
            <div className="border-b border-border px-5 py-3 font-mono text-xs uppercase tracking-[0.18em] text-cyan">Conversation</div>
            <div className="min-h-0 flex-1 space-y-4 overflow-auto p-5">
              {messages.length === 0 ? <div className="font-mono text-dim">Start a new investigation.</div> : null}
              {messages.map((message, index) => (
                <div key={`${message.timestamp}-${index}`} className={`rounded-xl border p-4 ${message.role === 'assistant' ? 'border-cyan/20 bg-cyan/5' : 'border-border bg-panel2'}`}>
                  <div className="mb-2 flex items-center justify-between">
                    <div className="font-mono text-xs uppercase tracking-[0.18em] text-dim">{message.role === 'assistant' ? 'SecurityClaw' : 'Operator'}</div>
                    {message.routing_skills?.length ? <div className="flex flex-wrap gap-2">{message.routing_skills.map((skill) => <span key={skill} className="badge badge-green">{skill}</span>)}</div> : null}
                  </div>
                  <div className="markdown text-sm">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                  </div>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
            <div className="border-t border-border p-4">
              <div className="flex flex-col gap-2">
                <textarea
                  className="textarea min-h-24 flex-1"
                  placeholder="Ask SecurityClaw to investigate, query, compare, or triage... Press Enter to send, Shift+Enter for new line"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                />
                <button className="btn btn-primary self-start" onClick={send} disabled={busy || !input.trim()}>
                  <Send className="h-4 w-4" /> {busy ? 'RUNNING' : 'SEND'}
                </button>
              </div>
            </div>
          </div>

          <div className="panel flex min-h-0 flex-col overflow-hidden">
            <div className="border-b border-border px-5 py-3 font-mono text-xs uppercase tracking-[0.18em] text-cyan">Reasoning Steps</div>
            <div className="min-h-0 flex-1 space-y-3 overflow-auto p-5">
              {steps.length === 0 ? <div className="font-mono text-dim">No active steps.</div> : null}
              {steps.map((step, index) => (
                <div key={`${step.kind}-${index}`} className="rounded-xl border border-border bg-panel2 p-4">
                  <div className="mb-2"><StepChip step={step} /></div>
                  <div className="text-sm text-text">{step.detail}</div>
                  {step.skills?.length ? <div className="mt-3 flex flex-wrap gap-2">{step.skills.map((skill) => <span key={skill} className="badge badge-dim">{skill}</span>)}</div> : null}
                </div>
              ))}
              <div ref={stepsEndRef} />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
