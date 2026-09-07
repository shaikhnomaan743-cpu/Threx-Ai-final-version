import { useEffect, useRef } from 'react';

export default function PipelineViz({ paused=false, flowRate=88 }: { paused?:boolean; flowRate?:number }) {
  const cvRef = useRef<HTMLCanvasElement>(null);
  const pRef = useRef(paused); pRef.current = paused;
  const frRef = useRef(flowRate); frRef.current = flowRate;

  useEffect(() => {
    const cv = cvRef.current;
    if (!cv || !window.THREE) return;
    const THREE = window.THREE;
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x0a0f14, 0.04);
    const cam = new THREE.PerspectiveCamera(44, 1, .1, 100);
    cam.position.set(0, 1.2, 18);
    const rend = new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:false});
    rend.setClearColor(0x0a0f14, 1);

    const N = 3500;
    const pos = new Float32Array(N*3), col = new Float32Array(N*3), siz = new Float32Array(N);
    const vel = new Float32Array(N), rad = new Float32Array(N), ang = new Float32Array(N), spn = new Float32Array(N);
    const COLD=new THREE.Color(0x0a2a3a), MID=new THREE.Color(0x0a8a7a), HOT=new THREE.Color(0x0ee6c8), ALERT=new THREE.Color(0xf04050), tmp=new THREE.Color();

    function spawn(i:number) {
      pos[i*3]=-15-Math.random()*8; rad[i]=1+Math.pow(Math.random(),.5)*4.2;
      ang[i]=Math.random()*Math.PI*2; spn[i]=(Math.random()-.5)*.4;
      // speed proportional to flow rate
      const speedMult = Math.max(0.5, Math.min(2, frRef.current / 88));
      vel[i]=(.025+Math.random()*.04)*speedMult;
      siz[i]=.4+Math.random()*1.2;
    }
    for(let i=0;i<N;i++) spawn(i);

    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
    geo.setAttribute('aCol',new THREE.BufferAttribute(col,3));
    geo.setAttribute('aSize',new THREE.BufferAttribute(siz,1));

    const c2=document.createElement('canvas'); c2.width=c2.height=64;
    const cx=c2.getContext('2d')!;
    const gr=cx.createRadialGradient(32,32,0,32,32,32);
    gr.addColorStop(0,'rgba(255,255,255,1)'); gr.addColorStop(.25,'rgba(255,255,255,.5)');
    gr.addColorStop(1,'rgba(255,255,255,0)'); cx.fillStyle=gr; cx.fillRect(0,0,64,64);

    const mat = new THREE.ShaderMaterial({
      uniforms:{map:{value:new THREE.CanvasTexture(c2)},dpr:{value:1}},
      vertexShader:`attribute float aSize;attribute vec3 aCol;varying vec3 vC;uniform float dpr;
        void main(){vC=aCol;vec4 mv=modelViewMatrix*vec4(position,1.);
        gl_PointSize=max(1.,aSize*dpr*(120./max(.001,-mv.z)));gl_Position=projectionMatrix*mv;}`,
      fragmentShader:`uniform sampler2D map;varying vec3 vC;
        void main(){vec4 t=texture2D(map,gl_PointCoord);if(t.a<.01)discard;gl_FragColor=vec4(vC,1.)*t;}`,
      transparent:true,depthWrite:false,blending:THREE.AdditiveBlending,
    });
    scene.add(new THREE.Points(geo,mat));

    // diode aperture
    const mkRing=(r:number,tube:number,op:number)=>{
      const m=new THREE.Mesh(new THREE.TorusGeometry(r,tube,8,80),new THREE.MeshBasicMaterial({color:0x0ee6c8,transparent:true,opacity:op,blending:THREE.AdditiveBlending,depthWrite:false}));
      m.rotation.y=Math.PI/2; m.position.x=-4; scene.add(m); return m;
    };
    const r1=mkRing(1.5,.012,.6), r2=mkRing(2.4,.006,.15);
    const vl=new THREE.Mesh(new THREE.PlaneGeometry(.02,8),new THREE.MeshBasicMaterial({color:0x0ee6c8,transparent:true,opacity:.06,blending:THREE.AdditiveBlending,depthWrite:false,side:THREE.DoubleSide}));
    vl.position.x=-4; scene.add(vl);
    // core
    const core=new THREE.Mesh(new THREE.IcosahedronGeometry(.5,1),new THREE.MeshBasicMaterial({color:0x8060f0,wireframe:true,transparent:true,opacity:.3,blending:THREE.AdditiveBlending,depthWrite:false}));
    core.position.x=2; scene.add(core);
    const glow=new THREE.Mesh(new THREE.SphereGeometry(.2,16,16),new THREE.MeshBasicMaterial({color:0xc0b0ff,transparent:true,opacity:.6,blending:THREE.AdditiveBlending,depthWrite:false}));
    glow.position.x=2; scene.add(glow);
    // seal
    const seal=new THREE.Mesh(new THREE.TorusGeometry(.7,.01,6,48),new THREE.MeshBasicMaterial({color:0x20c070,transparent:true,opacity:.3,blending:THREE.AdditiveBlending,depthWrite:false}));
    seal.position.x=7; seal.rotation.y=Math.PI/2; scene.add(seal);

    let mx=0,my=0,tx=0,ty=0;
    const onP=(e:PointerEvent)=>{const r=cv.getBoundingClientRect();tx=(e.clientX-r.left)/r.width-.5;ty=(e.clientY-r.top)/r.height-.5};
    cv.parentElement?.addEventListener('pointermove',onP);

    function resize(){
      const r=cv.getBoundingClientRect(),dpr=Math.min(window.devicePixelRatio||1,2);
      rend.setPixelRatio(dpr);rend.setSize(r.width,r.height,false);
      cam.aspect=r.width/Math.max(r.height,1);cam.updateProjectionMatrix();
      mat.uniforms.dpr.value=dpr;
    }
    window.addEventListener('resize',resize); resize();

    let t=0;
    function frame(){
      requestAnimationFrame(frame);
      if(pRef.current) return;
      t+=.016;
      const P=geo.attributes.position.array as Float32Array;
      const C=geo.attributes.aCol.array as Float32Array;
      for(let i=0;i<N;i++){
        const i3=i*3;
        P[i3]+=vel[i]; ang[i]+=spn[i]*.016;
        const x=P[i3],through=x>-6;
        const tR=through?Math.max(.12,rad[i]*Math.max(0,1-(x+6)/18)):rad[i];
        P[i3+1]=Math.cos(ang[i])*tR; P[i3+2]=Math.sin(ang[i])*tR;
        const p=Math.max(0,Math.min(1,(x+15)/22));
        if(p<.3)tmp.copy(COLD).lerp(MID,p/.3);
        else if(p<.65)tmp.copy(MID).lerp(HOT,(p-.3)/.35);
        else tmp.copy(HOT).lerp(i%13===0?ALERT:MID,(p-.65)/.35);
        C[i3]=tmp.r;C[i3+1]=tmp.g;C[i3+2]=tmp.b;
        if(x>12) spawn(i);
      }
      geo.attributes.position.needsUpdate=true;
      geo.attributes.aCol.needsUpdate=true;
      core.rotation.x=t*.2;core.rotation.y=t*.35;
      (core.material as any).opacity=.25+Math.sin(t*1.8)*.08;
      r1.rotation.x=Math.sin(t*.3)*.06; r2.rotation.x=Math.sin(t*.25+1)*.04;
      seal.rotation.x=t*.25;seal.rotation.z=t*.18;
      mx+=(tx-mx)*.02;my+=(ty-my)*.02;
      cam.position.y=1.2+my*-1.2;cam.lookAt(-1,0,0);
      rend.render(scene,cam);
    }
    frame();
    return ()=>{window.removeEventListener('resize',resize);cv.parentElement?.removeEventListener('pointermove',onP);rend.dispose();geo.dispose();mat.dispose()};
  },[]);

  return <canvas ref={cvRef} style={{position:'absolute',inset:0,width:'100%',height:'100%',display:'block'}}/>;
}
