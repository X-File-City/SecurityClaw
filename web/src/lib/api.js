import axios from 'axios'

export const api = axios.create({
  timeout: 120000,
})

export async function streamChat({ message, conversationId, onEvent }) {
  const response = await fetch('/api/chat/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, conversation_id: conversationId }),
  })

  if (!response.ok || !response.body) {
    throw new Error(`Chat stream failed (${response.status})`)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    let splitIndex
    while ((splitIndex = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, splitIndex)
      buffer = buffer.slice(splitIndex + 2)
      const lines = chunk.split('\n')
      let event = 'message'
      let data = ''
      for (const line of lines) {
        if (line.startsWith('event: ')) event = line.slice(7)
        if (line.startsWith('data: ')) data += line.slice(6)
      }
      if (data) {
        onEvent?.(event, JSON.parse(data))
      }
    }
  }
}
