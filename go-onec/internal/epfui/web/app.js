'use strict';
const $ = id => document.getElementById(id);
let busy = false, closing = false, uncertain = false, contextState = null, methodCount = 0;
const pendingEdits = new Map(), fieldInputs = new Map();
const methodInfo = new Map(), argumentRows = [];
let nextInputID = 0;
const BOOLEAN_TYPE = '5D4125AD-F6E7-4313-BE32-F71D0AB60915';
const node = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const descriptions = {
  'Command dispatch requires the client runtime.':'Команда требует клиентского обработчика 1С.',
  'Field editing and client validation are disabled.':'Поле доступно только для чтения.',
  'Initial server state only; client BSL and client event handlers are not executed.':'Показано начальное состояние. Клиентский код BSL не выполняется.',
  'Bounded server context; client BSL, change handlers, validation, and command handlers are not executed.':'Поддерживается ограниченный контекст формы. Клиентский BSL, обработчики изменений, проверки и команды не выполняются.',
  'Presentation is simplified; layout, formatting, and conditional appearance are not reproduced.':'Раскладка упрощена. Оформление исходной формы не воспроизводится полностью.',
  'Form event metadata is present; no client event dispatch is performed.':'В форме есть события. Клиентские обработчики событий не вызываются.',
  'Bare undefined metadata values were normalized to null; their semantics are not interpreted.':'Значения undefined в описании формы отмечены как неопределённые.'
};
const errorDescriptions = {
  'Invalid scalar function arguments.':'Аргументы не соответствуют поддерживаемым типам. Вызов не отправлен.',
  'Invalid value for the field type.':'Значение поля не соответствует его типу. Вызов не отправлен.',
  'A call is already running.':'Другой вызов ещё выполняется. Дождитесь его завершения.',
  'Session is closing.':'Сеанс завершается.',
  'The call failed or its outcome is unconfirmed. It was not retried.':'Вызов завершился ошибкой или его результат не подтверждён. Автоматического повтора не было.',
  'The server reported an error. Form state was synchronized; the method was not retried.':'Сервер сообщил об ошибке. Состояние формы восстановлено с сервера. Метод повторно не запускался.',
  'The input was rejected before the call was sent.':'Данные не прошли проверку. Серверный метод не вызывался.',
  'The call outcome or form state is unconfirmed. Do not repeat the call; close this session.':'Результат вызова или состояние формы не подтверждены. Повтор отключён; завершите сеанс.',
  'The form changed in another request. Reload before editing again; this call was not sent.':'Форма изменилась в другом запросе. Загружена актуальная версия; этот вызов не отправлялся.'
};
const description = text => descriptions[text] || text;
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {cache:'no-store'} : {method:'POST', headers:{'Content-Type':'application/json','X-EPF-Request':'1'}, body:JSON.stringify(body), cache:'no-store'});
  if (!response.ok) {
    let data = {}; try { data = await response.json(); } catch {}
    const error = new Error(errorDescriptions[data.error] || data.error || 'Сеанс недоступен или запрос отклонён.');
    error.data = data; throw error;
  }
  return response.json();
}
function valueText(value) { if (!value) return 'Значение не поддерживается'; return typeof value.value === 'string' ? value.value : JSON.stringify(value.value); }
function setStatus(text, state = '') {
  $('status').textContent = text;
  $('status').className = 'status' + (state ? ' ' + state : '');
}
function setResult(text, label, state = '') {
  $('result').textContent = text;
  $('result-state').textContent = label;
  $('result-state').className = 'result-state' + (state ? ' ' + state : '');
}
function updateDraftCount() {
  $('draft-count').hidden = pendingEdits.size === 0;
  $('draft-count').textContent = 'Изменено полей: ' + pendingEdits.size;
}
function decodeArgumentDraft(raw) {
  if (!Array.isArray(raw) || raw.length > 32) throw new Error('Нужен JSON-массив: не более 32 аргументов.');
  return raw.map(value => {
    if (typeof value === 'string') return {type:'string', value};
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'type,value') throw new Error('У аргумента должны быть только поля type и value.');
    const type = typeof value.type === 'string' ? value.type.toLowerCase() : '';
    if (!['string','number','boolean','date'].includes(type) || typeof value.value !== (type === 'boolean' ? 'boolean' : 'string')) throw new Error('Допустимы строки, числа текстом, логические значения и даты текстом.');
    return {type, value:value.value};
  });
}
function fieldArguments() {
  return argumentRows.map(item => item.type.value === 'string' ? item.read() : {type:item.type.value, value:item.read()});
}
function refreshArgumentLabels() {
  argumentRows.forEach((item, index) => {
    item.label.textContent = 'Аргумент ' + (index + 1);
    item.type.setAttribute('aria-label', 'Тип аргумента ' + (index + 1));
    item.remove.setAttribute('aria-label', 'Удалить аргумент ' + (index + 1));
  });
  $('arguments-empty').hidden = argumentRows.length > 0;
  updateControls();
}
function addArgument(type = 'string', value = '') {
  if (argumentRows.length >= 32) return;
  const row = node('div', undefined, 'argument-row'), head = node('div', undefined, 'argument-row-head');
  const label = node('label'), remove = node('button', 'Удалить', 'secondary');
  remove.type = 'button';
  const inputs = node('div', undefined, 'argument-inputs'), selector = node('select'), valueBox = node('div');
  for (const [key, title] of [['string','Строка'],['number','Число'],['boolean','Да / Нет'],['date','Дата']]) {
    const option = node('option', title); option.value = key; selector.append(option);
  }
  selector.value = type;
  const id = 'argument-value-' + (++nextInputID); label.htmlFor = id;
  let input;
  const renderValue = initial => {
    input = node(selector.value === 'boolean' ? 'select' : 'input'); input.id = id;
    if (selector.value === 'boolean') {
      for (const [key, title] of [['false','Нет'],['true','Да']]) { const option = node('option', title); option.value = key; input.append(option); }
      input.value = String(initial === true);
    } else {
      input.value = typeof initial === 'string' ? initial : '';
      input.placeholder = selector.value === 'number' ? '12.50' : selector.value === 'date' ? '2026-10-23T12:00:00' : 'Значение';
      if (selector.value === 'number') input.inputMode = 'decimal';
    }
    valueBox.replaceChildren(input);
  };
  renderValue(value);
  const item = {row, label, type:selector, remove, read:() => selector.value === 'boolean' ? input.value === 'true' : input.value};
  selector.addEventListener('change', () => renderValue(''));
  remove.addEventListener('click', () => { argumentRows.splice(argumentRows.indexOf(item), 1); row.remove(); refreshArgumentLabels(); $('add-argument').focus(); });
  head.append(label, remove); inputs.append(selector, valueBox); row.append(head, inputs);
  argumentRows.push(item); $('argument-list').append(row); refreshArgumentLabels();
}
function updateMethodNote() {
  const method = methodInfo.get($('method').value);
  $('method-note').textContent = method ? 'Параметров по описанию формы: ' + method.parameter_count + '. Значения задаются явно.' : 'В этой форме нет доступных серверных функций для выбранного режима.';
}
function updateControls() {
  const locked = busy || closing || uncertain || !!(contextState && !contextState.usable);
  $('call').disabled = locked || !methodCount;
  $('call').textContent = busy ? 'Выполняется…' : 'Вызвать функцию';
  $('method').disabled = locked || !methodCount;
  $('function-panel').setAttribute('aria-busy', String(busy));
  for (const input of $('argument-controls').querySelectorAll('input, select, textarea, button')) input.disabled = locked || !methodCount;
  $('add-argument').disabled = locked || !methodCount || argumentRows.length >= 32;
  for (const inputs of fieldInputs.values()) for (const input of inputs) {
    input.readOnly = locked || !contextState?.usable;
    if (input.type === 'checkbox') input.disabled = input.readOnly;
  }
}
function renderElement(element, parent) {
  if (!element.visible) return;
  const box = node('div', undefined, 'element '+element.kind);
  const canonical = contextState?.editable_fields?.find(name => name.toUpperCase() === (element.data_path || '').toUpperCase());
  const editable = !!canonical && !element.read_only && element.enabled && contextState.usable;
  if (element.kind === 'field') {
    const label = node('label',element.title || element.name);
    const input = node('input');
    input.id = 'form-field-' + (++nextInputID); label.htmlFor = input.id;
    const isBoolean = element.value?.type === BOOLEAN_TYPE;
    if (isBoolean) { input.type = 'checkbox'; input.checked = element.value.value; input.disabled = !editable; label.className = 'boolean-field'; label.prepend(input); box.append(label); }
    else { input.value = valueText(element.value); box.append(label, input); }
    input.readOnly = !editable; input.setAttribute('aria-label',element.title || element.name);
    if (editable) {
      const inputs = fieldInputs.get(canonical) || []; inputs.push(input); fieldInputs.set(canonical,inputs);
      const readValue = () => isBoolean ? String(input.checked) : input.value;
      const original = readValue();
      input.addEventListener('input',()=>{
        const value = readValue();
        if (value === original) pendingEdits.delete(canonical); else pendingEdits.set(canonical,value);
        for (const other of fieldInputs.get(canonical)) if (other !== input) { other.value = value; if (isBoolean) other.checked = input.checked; }
        updateDraftCount();
        setStatus(pendingEdits.size ? 'Есть изменения. Они отправятся вместе с выбранной функцией.' : 'Состояние формы синхронизировано.', pendingEdits.size ? 'warning' : 'success');
      });
      box.append(node('p','Изменение отправляется при вызове функции.','hint'));
    }
  } else if (element.kind === 'button') {
    const button = node('button', element.title || element.name, 'secondary'); button.disabled = true; button.title = 'Требуется клиентский обработчик 1С'; box.append(button);
  } else if (element.kind === 'decoration') box.append(node('p',element.title || element.name,'decoration-label'));
  else box.append(node('div',element.title || element.name || element.kind,'element-title'));
  const unsupported = (element.unsupported || []).filter(text => !editable || text !== 'Field editing and client validation are disabled.');
  if (unsupported.length) box.append(node('p',unsupported.map(description).join(' · '),'hint'));
  for (const child of element.children || []) renderElement(child,box);
  parent.append(box);
}
function renderSnapshot(snapshot) {
  pendingEdits.clear(); fieldInputs.clear(); $('form').replaceChildren(); $('warnings').replaceChildren();
  updateDraftCount();
  $('form-title').textContent = snapshot.title || 'Управляемая форма';
  const system = node('details',undefined,'system-elements'); system.append(node('summary','Служебные элементы формы'));
  for (const element of snapshot.elements || []) renderElement(element,['AutoCommandBar','Navigator'].includes(element.variant) ? system : $('form'));
  if (system.children.length > 1) $('form').append(system);
  if (!$('form').children.length) $('form').append(node('p','Поддерживаемые элементы не найдены.'));
  const notes = node('details'); notes.append(node('summary','Ограничения поддержки формы'));
  for (const warning of snapshot.warnings || []) notes.append(node('p',description(warning)));
  if (snapshot.warnings?.length) $('warnings').append(notes);
  $('mode-badge').textContent = contextState ? (contextState.usable ? 'Редактирование · версия '+contextState.revision : 'Состояние не подтверждено') : 'Только чтение';
  $('mode-badge').className = 'badge ' + (contextState?.usable ? 'editable' : 'warning');
  updateControls();
}
function acceptState(state) { contextState = state; renderSnapshot(state.snapshot); }
async function init() {
  try {
    const model = await api('api/state'); contextState = model.context || null;
    if (contextState) {
      $('call-description').textContent = 'Функции с контекстом формы. Изменённые поля отправляются вместе с вызовом.';
      $('scope-note').textContent = 'Поддерживаются строки, числа, логические значения, даты и аргументы серверных функций. Применяются поддержанные изменения заголовка, видимости и доступности полей. Клиентские обработчики BSL, штатные кнопки, таблицы и точная раскладка здесь не исполняются.';
      $('state-note').textContent = 'После подтверждённого вызова применяются серверные изменения. При неопределённом исходе дальнейшие вызовы отключаются; автоматического повтора нет.';
    }
    renderSnapshot(model.snapshot);
    $('method').replaceChildren();
    $('method-total').textContent = (model.methods || []).length;
    for (const method of model.methods || []) {
      const available = method.exported && method.context === (contextState ? 'server' : 'no-context') && method.kind === 'function';
      const row = node('div',undefined,'method-row'); row.append(node('code',method.name)); row.append(node('span',available ? 'аргументов: '+method.parameter_count : method.context+' / '+method.kind,available ? 'available' : 'hint')); $('methods').append(row);
      if (available) { const option = node('option',method.name); option.value=method.name; $('method').append(option); methodInfo.set(method.name, method); methodCount++; }
    }
    if (!methodCount) $('method').append(node('option', 'Нет доступных функций'));
    updateControls();
    updateMethodNote();
    if (contextState && !contextState.usable) setStatus('Состояние формы не подтверждено. Завершите сеанс.', 'error');
    else setStatus('Сеанс открыт. Форма загружена с сервера.', 'success');
  } catch (error) { setStatus(error.message, 'error'); }
}
$('method').addEventListener('change', updateMethodNote);
$('add-argument').addEventListener('click', () => { addArgument(); argumentRows.at(-1)?.row.querySelector('input')?.focus(); });
$('argument-mode').addEventListener('change', () => {
  const json = $('argument-mode').value === 'json';
  if (json) $('arguments').value = JSON.stringify(fieldArguments(), null, 2);
  else {
    try {
      const values = decodeArgumentDraft(JSON.parse($('arguments').value));
      argumentRows.length = 0; $('argument-list').replaceChildren();
      for (const value of values) addArgument(value.type, value.value);
      refreshArgumentLabels();
    } catch (error) { $('argument-mode').value = 'json'; setResult('Не удалось перейти к полям: ' + error.message, 'Проверьте аргументы', 'error'); return; }
  }
  $('argument-fields').hidden = json; $('argument-json').hidden = !json;
});
for (const link of document.querySelectorAll('.nav-link')) link.addEventListener('click', () => {
  for (const other of document.querySelectorAll('.nav-link')) { other.classList.remove('active'); other.removeAttribute('aria-current'); }
  link.classList.add('active'); link.setAttribute('aria-current', 'location');
  if (link.getAttribute('href') === '#session-details') $('session-details').open = true;
});
$('call').addEventListener('click',async()=>{
  if (busy || closing || uncertain || !methodCount || (contextState && !contextState.usable)) return;
  let body, path;
  let args;
  try {
    args = $('argument-mode').value === 'json' ? JSON.parse($('arguments').value) : fieldArguments();
    decodeArgumentDraft(args);
  } catch (error) { setResult('Проверьте аргументы: ' + error.message, 'Не отправлено', 'error'); return; }
  if (contextState) {
    body = {method:$('method').value,revision:contextState.revision,arguments:args,changes:Array.from(pendingEdits,([name,value])=>({name,value}))}; path='api/context-call';
  } else {
    body={method:$('method').value,arguments:args}; path='api/call';
  }
  busy=true; updateControls(); setResult('Ожидаю ответ сервера…', 'Выполняется'); setStatus('Функция выполняется. Дождитесь ответа.');
  try {
    const result=await api(path,body); if (result.state) acceptState(result.state);
    setResult(valueText(result.value), 'Выполнено', 'success');
    if (!closing) setStatus(contextState ? 'Вызов завершён. Серверные изменения применены.' : 'Вызов завершён.', 'success');
  } catch(error) {
    if (error.data?.state) {
      const state=error.data.state;
      // A local rejection at the same revision must not discard the draft.
      if (error.data.submitted === false && contextState?.revision === state.revision && state.usable) contextState=state;
      else acceptState(state);
    }
    else if (error.data?.submitted !== false) {
      uncertain=true;
      if (contextState) contextState.usable=false;
      $('mode-badge').textContent = 'Результат не подтверждён'; $('mode-badge').className = 'badge warning';
    }
    setResult(error.message, error.data?.submitted === false ? 'Не отправлено' : 'Ошибка вызова', 'error');
    if (!closing) setStatus(error.data?.recovered ? 'Ошибка метода. Состояние восстановлено; можно продолжать работу.' : uncertain ? error.message + ' Повтор отключён. Завершите сеанс.' : error.message, 'error');
  } finally { busy=false; updateControls(); }
});
$('close').addEventListener('click',async()=>{
  if (closing) return;
  closing=true; $('close').disabled=true; updateControls();
  $('close').textContent = 'Завершение…';
  try { await api('api/close',{}); setStatus('Завершаю сеанс. Подтверждение закрытия формы и выхода будет в отчёте CLI.'); }
  catch(error) { setStatus(error.message+' Остановите CLI или дождитесь истечения срока сеанса.', 'error'); }
});
updateControls();
init();
