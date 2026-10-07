import type { components } from './api.generated';
export type Device = components['schemas']['Device'];
export type Health = components['schemas']['Health'];
export type Instruction = components['schemas']['Instruction'];
export type Me = components['schemas']['Me'];
export type Overview = components['schemas']['Overview'];
export class APIError extends Error {constructor(public status:number,message:string){super(message);}}
async function request<T>(path:string,body?:unknown,csrf?:string):Promise<T>{
 const res=await fetch(`/api/v1${path}`,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(15000),headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf??''},body:body===undefined?undefined:JSON.stringify(body)});
 if(!res.ok){const data=await res.json().catch(()=>null);throw new APIError(res.status,data?.error?.message??`Сервис не ответил (${res.status}). Попробуйте ещё раз.`);}
 return res.status===204?undefined as T:res.json() as Promise<T>;
}
export const api={
	adminUsers:(after='')=>request<components['schemas']['AdminUserPage']>(`/admin/users?limit=25&after=${encodeURIComponent(after)}`),
	adminDevices:(state='pending',after='')=>request<components['schemas']['AdminDevicePage']>(`/admin/devices?limit=25&state=${encodeURIComponent(state)}&after=${encodeURIComponent(after)}`),
	adminAudit:(after='')=>request<components['schemas']['AdminAuditEventPage']>(`/admin/audit?limit=25&after=${encodeURIComponent(after)}`),
 deviceQuota:()=>request<components['schemas']['DeviceQuota']>('/devices/quota'),
 requestDevice:(body:components['schemas']['DeviceRequest'],csrf:string)=>request<Device>('/devices',body,csrf),
 renameDevice:(id:string,body:components['schemas']['DeviceRename'],csrf:string)=>request<Device>(`/devices/${encodeURIComponent(id)}/rename`,body,csrf),
 cancelDevice:(id:string,body:components['schemas']['DeviceRevision'],csrf:string)=>request<Device>(`/devices/${encodeURIComponent(id)}/cancel`,body,csrf),
 me:()=>request<Me>('/me'),devices:()=>request<{items:Device[]}>('/devices'),
 status:()=>request<{items:Health[]}>('/status'),instructions:()=>request<{items:Instruction[]}>('/instructions'),overview:()=>request<Overview>('/admin/overview'),
 adminPassword:(body:components['schemas']['PasswordLogin'],csrf:string)=>request<components['schemas']['AdminChallenge']>('/auth/admin/password',body,csrf),
 adminTOTP:(body:components['schemas']['AdminTOTP'],csrf:string)=>request<components['schemas']['AdminAuthResult']>('/auth/admin/totp',body,csrf),
 bootstrap:()=>request<components['schemas']['AuthBootstrap']>('/auth/bootstrap'),
 login:(body:components['schemas']['PasswordLogin'],csrf:string)=>request<components['schemas']['AuthResult']>('/auth/login',body,csrf),
 accept:(body:components['schemas']['AcceptInvitation'],csrf:string)=>request<components['schemas']['AuthResult']>('/auth/invitations/accept',body,csrf),
 recover:(body:components['schemas']['RecoveryProof'],csrf:string)=>request<void>('/auth/recovery/consume',body,csrf),
 logout:(csrf:string)=>request<void>('/auth/logout',{},csrf),touch:(csrf:string)=>request<void>('/auth/session/touch',{},csrf)
};
