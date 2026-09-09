local _kQ0=(function()local band,bor,bxor,bnot=bit32.band,bit32.bor,bit32.bxor,bit32.bnot
  local lshift,rshift=bit32.lshift,bit32.rshift
  local byte,char,rep,sub=string.byte,string.char,string.rep,string.sub
  local M32=4294967295
  local MOD32=4294967296
  local function rotl(v,s)return bor(lshift(v,s),rshift(v,32-s))
    end
  local function rotr(v,s)return bor(rshift(v,s),lshift(v,32-s))
    end
  local function le32(s,i)local a,b,c,d=byte(s,i,i+3)
    return((a+b*256)+c*65536)+d*16777216
    end
  local function bytes_out(t,n)local chunks=table.create((n+127)//128)
    local k=0
    local i=1
    while i<=n do local j=i+127
      if j>n then j=n
        end
      k+=1
      chunks[k]=char(table.unpack(t,i,j))
      i=j+1
      end
    return table.concat(chunks)
    end
  local SIGMA={1634760805,857760878,2036477234,1797285236}
  local cstate=table.create(16)
  local cwork=table.create(16)
  local function qr(s,a,b,c,d)s[a]=band(s[a]+s[b],M32)
    s[d]=rotl(bxor(s[d],s[a]),16)
    s[c]=band(s[c]+s[d],M32)
    s[b]=rotl(bxor(s[b],s[c]),12)
    s[a]=band(s[a]+s[b],M32)
    s[d]=rotl(bxor(s[d],s[a]),8)
    s[c]=band(s[c]+s[d],M32)
    s[b]=rotl(bxor(s[b],s[c]),7)
    end
  local function chacha_block(key32,counter,nonce12,out)local s=cstate
    s[1],s[2],s[3],s[4]=SIGMA[1],SIGMA[2],SIGMA[3],SIGMA[4]
    for i=1,8 do s[4+i]=key32[i]
      end
    s[13]=band(counter,M32)
    s[14]=nonce12[1]
    s[15]=nonce12[2]
    s[16]=nonce12[3]
    local w=cwork
    for i=1,16 do w[i]=s[i]
      end
    for _=1,10 do qr(w,1,5,9,13)
      qr(w,2,6,10,14)
      qr(w,3,7,11,15)
      qr(w,4,8,12,16)
      qr(w,1,6,11,16)
      qr(w,2,7,12,13)
      qr(w,3,8,9,14)
      qr(w,4,5,10,15)
      end
    local p=1
    for i=1,16 do local v=band(w[i]+s[i],M32)
      out[p]=band(v,255)
      out[p+1]=band(rshift(v,8),255)
      out[p+2]=band(rshift(v,16),255)
      out[p+3]=band(rshift(v,24),255)
      p+=4
      end
    end
  local function prep_key(keystr)local k=table.create(8)
    for i=1,8 do k[i]=le32(keystr,(i-1)*4+1)
      end
    return k
    end
  local function prep_nonce(noncestr)return{le32(noncestr,1),le32(noncestr,5),le32(noncestr,9)}
    end
  local keystream=table.create(64)
  local function _kQa(keystr,noncestr,data,counter)local key32=prep_key(keystr)
    local nonce12=prep_nonce(noncestr)
    local len=#data
    local out=table.create(len)
    local ks=keystream
    local blk=0
    local pos=1
    while pos<=len do chacha_block(key32,counter+blk,nonce12,ks)
      blk+=1
      local stop=pos+63
      if stop>len then stop=len
        end
      for i=pos,stop do out[i]=bxor(byte(data,i),ks[(i-pos)+1])
        end
      pos=stop+1
      end
    return bytes_out(out,len)
    end
  local SHA_K={1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298}
  local SHA_H={1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225}
  local wbuf=table.create(64)
  local function sha256_blocks(state,msg,start,blocks)local w=wbuf
    for b=0,blocks-1 do local base=start+b*64
      for i=1,16 do local o=base+(i-1)*4
        local x,y,z,t=byte(msg,o,o+3)
        w[i]=((x*16777216+y*65536)+z*256)+t
        end
      for i=17,64 do local a=w[i-15]
        local s0=bxor(bxor(rotr(a,7),rotr(a,18)),rshift(a,3))
        local c=w[i-2]
        local s1=bxor(bxor(rotr(c,17),rotr(c,19)),rshift(c,10))
        w[i]=(((w[i-16]+s0)+w[i-7])+s1)%MOD32
        end
      local h1,h2,h3,h4=state[1],state[2],state[3],state[4]
      local h5,h6,h7,h8=state[5],state[6],state[7],state[8]
      for i=1,64 do local S1=bxor(bxor(rotr(h5,6),rotr(h5,11)),rotr(h5,25))
        local ch=bxor(band(h5,h6),band(bnot(h5),h7))
        local t1=((((h8+S1)+ch)+SHA_K[i])+w[i])%MOD32
        local S0=bxor(bxor(rotr(h1,2),rotr(h1,13)),rotr(h1,22))
        local maj=bxor(bxor(band(h1,h2),band(h1,h3)),band(h2,h3))
        local t2=(S0+maj)%MOD32
        h8=h7
        h7=h6
        h6=h5
        h5=(h4+t1)%MOD32
        h4=h3
        h3=h2
        h2=h1
        h1=(t1+t2)%MOD32
        end
      state[1]=(state[1]+h1)%MOD32
      state[2]=(state[2]+h2)%MOD32
      state[3]=(state[3]+h3)%MOD32
      state[4]=(state[4]+h4)%MOD32
      state[5]=(state[5]+h5)%MOD32
      state[6]=(state[6]+h6)%MOD32
      state[7]=(state[7]+h7)%MOD32
      state[8]=(state[8]+h8)%MOD32
      end
    end
  local function _kQb(msg)local state=table.create(8)
    for i=1,8 do state[i]=SHA_H[i]
      end
    local len=#msg
    local padded=len+1
    while padded%64~=56 do padded+=1
      end
    padded+=8
    local tail=table.create((padded-len)-8)
    tail[1]="\128"
    for i=2,(padded-len)-8 do tail[i]="\000"
      end
    local bits=len*8
    local lenbytes=table.create(8)
    for i=8,1,-1 do lenbytes[i]=char(band(bits,255))
      bits=(bits-band(bits,255))//256
      end
    local full=msg..table.concat(tail)..table.concat(lenbytes)
    sha256_blocks(state,full,1,padded//64)
    local out=table.create(32)
    for i=1,8 do local v=state[i]
      out[(i-1)*4+1]=char(band(rshift(v,24),255))
      out[(i-1)*4+2]=char(band(rshift(v,16),255))
      out[(i-1)*4+3]=char(band(rshift(v,8),255))
      out[(i-1)*4+4]=char(band(v,255))
      end
    return table.concat(out)
    end
  local function _kQc(key,msg)if#key>64 then key=_kQb(key)
      end
    local inner=table.create(64)
    local outer=table.create(64)
    for i=1,64 do local v=byte(key,i)or 0
      inner[i]=char(bxor(v,54))
      outer[i]=char(bxor(v,92))
      end
    return _kQb(table.concat(outer).._kQb(table.concat(inner)..msg))
    end
  local function le64(n)local t=table.create(8)
    for i=1,8 do t[i]=char(band(n,255))
      n=(n-band(n,255))//256
      end
    return table.concat(t)
    end
  local function mac_key(keystr,noncestr)return _kQb("couxobf-mac-v1\000"..keystr..noncestr)
    end
  local function compute_tag(keystr,noncestr,ct,aad)local covered={noncestr,aad,le64(#aad),ct,le64(#ct)}
    return _kQc(mac_key(keystr,noncestr),table.concat(covered))
    end
  local function const_eq(a,b)if#a~=#b then return false
      end
    local diff=0
    for i=1,#a do diff=bor(diff,bxor(byte(a,i),byte(b,i)))
      end
    return diff==0
    end
  local function _kQd(keystr,noncestr,ct,tag,aad)aad=aad or""
    if not const_eq(compute_tag(keystr,noncestr,ct,aad),tag)then return nil
      end
    return _kQa(keystr,noncestr,ct,1)
    end
  local function _kQe(keystr,noncestr,plain,aad)aad=aad or""
    local ct=_kQa(keystr,noncestr,plain,1)
    return ct,compute_tag(keystr,noncestr,ct,aad)
    end
  return{_kQa=_kQa,_kQb=_kQb,_kQc=_kQc,_kQd=_kQd,_kQe=_kQe}
  end)()
local _kQ1="\150\147\1321\160\175\021B\192\138H\003\205;\018h\013`d\247VLX\014\143\031o\173\227\024\188\134"
local _kQ2="\2322\245cjd\\]6+\135\013"
local _kQ3="\133A\153\004\005\013J\235\247\242X\170\011L \156Y\224\196\169\181\160\131\231[#\246y\140\143\179\003"
local _kQ4="\132l.vH\001\242E\\\181e\216\030\030\016\188Dzwu\160\163\223\198,\185\145\202B\233\234\243h\150\019\160\025l\244\159\0121\200\129"
local _kQ5=nil
local _kQ6=nil
local _kQ7=false
local function _kQ8()if _kQ7 then return
    end
  _kQ7=true
  local p=_kQ0._kQd(_kQ1,_kQ2,_kQ4,_kQ3,"couxobf/constpool/v1\000hello_fn.luau")
  if p==nil then error("constant pool failed authentication")
    end
  _kQ5=p
  local o={}
  local count=string.unpack(">I4",p,1)
  local q=5
  for i=1,count do o[i]=q
    local t=string.byte(p,q)
    q+=1
    if t==2 then q+=8
      elseif t==3 then q+=4+string.unpack(">I4",p,q)
      elseif t==1 then q+=1
      end
    end
  _kQ6=o
  end
local function _kQ9(i)local p=_kQ5
  local q=_kQ6[i]
  local t=string.byte(p,q)
  if t==0 then return nil
    elseif t==1 then return string.byte(p,q+1)~=0
    elseif t==2 then return string.unpack(">d",p,q+1)
    else local len=string.unpack(">I4",p,q+1)
    return string.sub(p,q+5,(q+4)+len)
    end
  end
local function _kQ10(i)_kQ8()
  return _kQ9(i)
  end
local _kS1="\012x\231C\013R\031C\005R\241\252\004\203\158\164\174\010\251\145fx\027\249\254{\156\165\213\136\011H,\205\225\192\213\162 VQ\203\220\161\223\201\1689\022\240Ay:\232\215\235\131\028\133\211\193\144\251\182,\228M\016\244\204\148+\205\160(c\195\253\130S#\\\191\222\220\245\232\242\237\236\158\222\174\202\015\136\006}\208\211A\201 \193\169a\137\008!\206.E\215`\205q\165[\031n\021V4\010\168\219\216\224T\017\151\0072\155\184b\"\160\0010\132\015\160\240\144\141\244\183\134\229\023\197,\235}j12\146\181lpkl\198r\195::$L\127\194K\"\146\028\195\188\253\196B\212*\238)\151'\228,\194X\176\245\152~I\199\171 \165\241\202\240rz\177v\237\210\234lX\148\029Bo]\2423\202\202\237\010\144J>.\185\130*\008\173\0172\019U\013\202@>\162\240\026\236\020\167\182\028\154\149\012\010\172\016\210\182qi\230\177\227$\157\238\164\175~\027\010-\161\166\1298\140\163\137`na\003d\176\213\146\005\215R\174dYe\157vG\164\231\026\181bn\023[\222S\0162\1635\127\161\213&\190\194\001\247\236D\021\252\214c\233\180\132+>V@\250\000\134\0131\231\025\209\198\255\176@S\240\215\144\231r\160%\011\015\008[l\222QA\158\191\144,J\225\132W\187\230\171\183\191llD\019\191\216I\195S\206>\178\253a?\129\183\243\009p\185\156\242\182fB\202\197L%$\188d\243k~T\030R\186\245\018\153fj<\215\201\206\187\188\187\180\1281\199\006\018J\241\226b\139Q\148\232\228\176$\"\223\175\145\148'\231\130_6\229\161\133\194\012-j\022\238\027n\180\164M\194\241V}H\132a$\224K\186 w\233~#v\167>p\025WIYB\179\227\153\166X\029\245=I>\148\213G\015\247\149bRzS\136b"
local _kS2="n\196\218m\182>\163\167\237\228\178\250rH\211\197b\230\219S\242'\148\251\196\183[p\155!L\224"
local _kS3="$|Q\187a_8\202g\026\235\161"
local _kS4="\027\162i\243~\147xQ\210\200\235\214\230\203^\222\127%m\004U9\175\199A\233\223\175}\166X\249"
local _kS5="\230\017X6\010\006\159\253\031\232R\\\001\165\227\151\028\224\246\132sbv\197\194\018Z\150"
local _kS6="\029\016\134\030n\156\165rx\233N<\227\161cG)\030\153+\161\245\164\254\207\026\001\144\020\133:,"
local _kS7="\139\202\226P\142]\143M\154#\164\139"
local _kSq="\202_\251n^>\193.n4\143\147a\237\1961\165Y\165i\008B\246\128\235\026\180\183?\167\149\129"
local _kSr="\137 @\009\004q=\012\187|t\149SM\000\015$O\230^\012\138\154f\153\002\172\1786\213\245\200"
local _kS8=nil
local _kS9=nil
local _kSa=nil
local _kSb=512
local _kSc=false
local function _kSd()if _kSc then return
    end
  _kSc=true
  if _kQ0._kQc(_kSq,_kS1)~=_kSr then error("string bank pages failed authentication")
    end
  local p=_kQ0._kQd(_kS2,_kS3,_kS5,_kS4,"couxobf/stringbank/v1\000hello_fn.luau")
  if p==nil then error("string bank failed authentication")
    end
  _kS8=p
  local tickets,pages=string.unpack(">I4I4",p,1)
  local psize=string.unpack(">I4",p,9)
  if psize~=_kSb then error("string bank page size mismatch")
    end
  local pm={}
  for i=1,pages do pm[i]=string.unpack(">I4",p,13+(i-1)*4)+1
    end
  _kS9=pm
  local q=13+pages*4
  local ix={}
  for i=1,tickets do ix[i]=q
    q+=2+string.unpack(">I2",p,q)*10
    end
  _kSa=ix
  end
local function _kSe(s,seed)local x=seed%2147483648
  local t=table.create(#s)
  for i=1,#s do x=(x*1103515+12345)%2147483648
    t[i]=string.char(bit32.bxor(string.byte(s,i),bit32.band(bit32.rshift(x,16),255)))
    end
  return table.concat(t)
  end
local function _kSf(off,len,seed)local page=off//_kSb
  local stored=_kS9[page+1]
  local inpage=off-page*_kSb
  local at=(stored-1)*_kSb+inpage
  local ct=string.sub(_kS1,at+1,at+len)
  local block=off//64
  local intra=off-block*64
  local ks=_kQ0._kQa(_kS6,_kS7,string.rep("\000",intra+len),1+block)
  local out=table.create(len)
  for i=1,len do out[i]=string.char(bit32.bxor(string.byte(ct,i),string.byte(ks,intra+i)))
    end
  return _kSe(table.concat(out),seed)
  end
local function _kSp(ticket)local p=_kS8
  local q=_kSa[ticket]
  if q==nil then error("string bank: bad ticket "..tostring(ticket))
    end
  local count=string.unpack(">I2",p,q)
  q+=2
  local parts={}
  local m=0
  for _=1,count do local off,len,seed=string.unpack(">I4I2I4",p,q)
    q+=10
    if len>0 then m+=1
      parts[m]=_kSf(off,len,seed)
      end
    end
  return table.concat(parts)
  end
local function _kSg(ticket)_kSd()
  return _kSp(ticket)
  end
local function _kpack(...)return table.pack(...)
  end
local function _kunpk(t,i)return table.unpack(t,i,t.n)
  end
local function _kiter(v)local mt=getmetatable(v)
  local m=mt and mt.__iter
  if m then return m(v)
    end
  if type(v)=="function"then return v
    end
  if mt and mt.__call then return v
    end
  if type(v)=="table"then return next,v,nil
    end
  error("attempt to iterate over a "..type(v).." value")
  end
local function _kiterpack(t)if t.n==1 then return _kiter(t[1])
    end
  return t[1],t[2],t[3]
  end
local function _kitercheck(f)local ty=type(f)
  if ty=="function"then return f
    end
  if(ty=="table"or ty=="userdata")or ty=="thread"then return f
    end
  error("attempt to iterate over a "..ty.." value")
  end
local function _kapp(dst,t)local n=#dst
  for i=1,t.n do n+=1
    dst[n]=t[i]
    end
  end
local _byte=string.byte
local _unpack=table.unpack
local _pack=table.pack
local __f4l=getfenv
local v_b79lQ=function(R,base,argc,tail)local f=R[base]
  if tail>=0 then local t=R[tail+1]
    local args={}
    for i=1,argc do args[i]=R[base+i]
      end
    local m=argc
    for i=1,t.n do m+=1
      args[m]=t[i]
      end
    return f(_unpack(args,1,m))
    end
  if argc==0 then return f()
    end
  return f(_unpack(R,base+1,base+argc))
  end
local function zD6z(p,R,E)local l_D2aO=p.code
  local K=p.consts
  local pc=(_byte(l_D2aO,7)+_byte(l_D2aO,8)*256)+1
  while true do local op=_byte(l_D2aO,pc)
    pc=pc+1
    if op==1 then local tbl=(_byte(l_D2aO,pc)+1)
      local pk=(_byte(l_D2aO,pc+1)+1)
      pc=pc+3
      _kapp(R[tbl],R[pk])
      elseif op==2 then pc=(_byte(l_D2aO,pc)+_byte(l_D2aO,pc+1)*256)+1
      elseif op==3 then local a,o,k=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[o][R[k]]
      elseif op==4 then local c=R[(_byte(l_D2aO,pc)+1)]
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      if c then pc=tgt+1
        end
      elseif op==5 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]<R[y]
      elseif op==6 then local base=(_byte(l_D2aO,pc)+1)
      local argc=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local tail=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)-1
      pc=pc+5
      return v_b79lQ(R,base,argc,tail)
      elseif op==7 then local o,v=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      local k=(_byte(l_D2aO,pc+2)+_byte(l_D2aO,(pc+2)+1)*256)
      pc=pc+4
      R[o][K[k+1]]=R[v]
      elseif op==8 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]>R[y]
      elseif op==9 then local a=(_byte(l_D2aO,pc)+1)
      local k=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      R[a]=E[K[k+1]]
      elseif op==10 then local base=(_byte(l_D2aO,pc)+1)
      local count=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      return _unpack(R,base,(base+count)-1)
      elseif op==11 then local k=(_byte(l_D2aO,pc)+_byte(l_D2aO,pc+1)*256)
      local v=(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      E[K[k+1]]=R[v]
      elseif op==12 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]^R[y]
      elseif op==13 then local a,x=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      pc=pc+2
      R[a]=#R[x]
      elseif op==14 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]%R[y]
      elseif op==15 then local base=(_byte(l_D2aO,pc)+1)
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      local i=R[base]+R[base+2]
      R[base]=i
      local lim,step=R[base+1],R[base+2]
      if(step>0 and i<=lim)or(step<0 and i>=lim)then R[base+3]=i
        pc=tgt+1
        end
      elseif op==16 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]//R[y]
      elseif op==17 then local base=(_byte(l_D2aO,pc)+1)
      local count=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local t=(_byte(l_D2aO,pc+3)+1)
      pc=pc+5
      local src=R[t]
      local out={}
      local m=count
      for i=0,count-1 do out[i+1]=R[base+i]
        end
      for i=1,src.n do m+=1
        out[m]=src[i]
        end
      if m==0 then return
        end
      return _unpack(out,1,m)
      elseif op==18 then local dst=(_byte(l_D2aO,pc)+1)
      local t=(_byte(l_D2aO,pc+1)+1)
      local count=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)
      pc=pc+5
      local src=R[t]
      for i=1,count do R[(dst+i)-1]=src[i]
        end
      elseif op==19 then local base=(_byte(l_D2aO,pc)+1)
      local argc=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local nres=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)-1
      local tail=(_byte(l_D2aO,pc+5)+_byte(l_D2aO,(pc+5)+1)*256)-1
      pc=pc+7
      local res=_pack(v_b79lQ(R,base,argc,tail))
      if nres<0 then R[base]=res
        else for i=1,nres do R[(base+i)-1]=res[i]
          end
        end
      elseif op==20 then local o,k,v=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[o][R[k]]=R[v]
      elseif op==21 then local a,x=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      pc=pc+2
      R[a]=not R[x]
      elseif op==22 then local tbl=(_byte(l_D2aO,pc)+1)
      local count=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local start=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)
      pc=pc+5
      local t=R[tbl]
      for i=1,count do t[(start+i)-1]=R[tbl+i]
        end
      elseif op==23 then local base=(_byte(l_D2aO,pc)+1)
      local packed=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      local h=packed==1 and _kiterpack or _kiter
      R[base],R[base+1],R[base+2]=h(R[base])
      elseif op==24 then local base=(_byte(l_D2aO,pc)+1)
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local resolved=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)
      pc=pc+5
      if resolved==0 then R[base]=_kitercheck(R[base])
        end
      pc=tgt+1
      elseif op==25 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]*R[y]
      elseif op==26 then local c=not R[(_byte(l_D2aO,pc)+1)]
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      if c then pc=tgt+1
        end
      elseif op==27 then local a,o=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      local k=(_byte(l_D2aO,pc+2)+_byte(l_D2aO,(pc+2)+1)*256)
      pc=pc+4
      local obj=R[o]
      R[a+1]=obj
      R[a]=obj[K[k+1]]
      elseif op==28 then local base=(_byte(l_D2aO,pc)+1)
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      local nvars=(_byte(l_D2aO,pc+3)+_byte(l_D2aO,(pc+3)+1)*256)
      pc=pc+5
      local f,s,c=R[base],R[base+1],R[base+2]
      local res=_pack(f(s,c))
      if res[1]~=nil then for i=0,nvars-1 do R[(base+3)+i]=res[i+1]
          end
        R[base+2]=res[1]
        pc=tgt+1
        end
      elseif op==29 then local a,o=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      local k=(_byte(l_D2aO,pc+2)+_byte(l_D2aO,(pc+2)+1)*256)
      pc=pc+4
      R[a]=R[o][K[k+1]]
      elseif op==30 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]+R[y]
      elseif op==31 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]/R[y]
      elseif op==32 then local a,x=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      pc=pc+2
      R[a]=-R[x]
      elseif op==33 then return
      elseif op==34 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]-R[y]
      elseif op==35 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]<=R[y]
      elseif op==36 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]..R[y]
      elseif op==37 then local a=(_byte(l_D2aO,pc)+1)
      pc=pc+1
      R[a]={}
      elseif op==38 then local a,s=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1)
      pc=pc+2
      R[a]=R[s]
      elseif op==39 then local a=(_byte(l_D2aO,pc)+1)
      local k=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      R[a]=K[k+1]
      elseif op==40 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]~=R[y]
      elseif op==41 then local base=(_byte(l_D2aO,pc)+1)
      local tgt=(_byte(l_D2aO,pc+1)+_byte(l_D2aO,(pc+1)+1)*256)
      pc=pc+3
      R[base]=R[base]-R[base+2]
      pc=tgt+1
      elseif op==42 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]==R[y]
      elseif op==43 then local a,x,y=(_byte(l_D2aO,pc)+1),(_byte(l_D2aO,pc+1)+1),(_byte(l_D2aO,pc+2)+1)
      pc=pc+3
      R[a]=R[x]>=R[y]
      else error("unknown opcode "..tostring(op))
      end
    end
  end
local function _gm7I(p,E,...)local R={}
  local args=_pack(...)
  for i=1,_byte(p.code,1)do R[i]=args[i]
    end
  return zD6z(p,R,E)
  end
local m9Sa1={[1]={code=_kQ10(2),consts={_kQ10(1)}}}
local _kR0={}
local _kC0=0
while true do if _kC0==0 then _kR0[0]=function(...)return _gm7I(m9Sa1[1],__f4l(1),...)
      end
    _kR0[1]=print
    _kR0[2]=_kR0[0]
    _kR0[3]=_kSg(1)
    _kR0[2]=_kpack(_kR0[2](_kR0[3]))
    _kR0[1](_kunpk(_kR0[2],1))
    return
    else break
    end
  end
