int
_dlerror_run (void (*operate) (void *), void *args)
{
  struct dl_action_result *result = __libc_dlerror_result;  //加载执行错误
  if (result != NULL)
    {
      if (result == dl_action_result_malloc_failed)
	{
	  /* Clear the previous error.  */
	  __libc_dlerror_result = NULL;
	  result = NULL;
	}
      else
	{
	  /* There is an existing object.  Free its error string, but
	     keep the object.  */
	  dl_action_result_errstring_free (result);
	  /* Mark the object as not containing an error.  This ensures
	     that call to dlerror from, for example, an ELF
	     constructor will not notice this result object.  */
	  result->errstring = NULL;
	}
    }
  const char *objname;
  const char *errstring;
  bool malloced;
  int errcode = GLRO (dl_catch_error) (&objname, &errstring, &malloced,
				       operate, args);
  /* ELF constructors or destructors may have indirectly altered the
     value of __libc_dlerror_result, therefore reload it.  */
  result = __libc_dlerror_result;
  if (errstring == NULL)
    {
      /* There is no error.  We no longer need the result object if it
	 does not contain an error.  However, a recursive call may
	 have added an error even if this call did not cause it.  Keep
	 the other error.  */
      if (result != NULL && result->errstring == NULL)
	{
	  __libc_dlerror_result = NULL;
	  free (result);
	}
      return 0;
    }
  else
    {
      /* A new error occurred.  Check if a result object has to be
	 allocated.  */
      if (result == NULL || result == dl_action_result_malloc_failed)
	{
	  /* Allocating storage for the error message after the fact
	     is not ideal.  But this avoids an infinite recursion in
	     case malloc itself calls libdl functions (without
	     triggering errors).  */
	  result = malloc (sizeof (*result));
	  if (result == NULL)
	    {
	      /* Assume that the dlfcn failure was due to a malloc
		 failure, too.  */
	      if (malloced)
		dl_error_free ((char *) errstring);
	      __libc_dlerror_result = dl_action_result_malloc_failed;
	      return 1;
	    }
	  __libc_dlerror_result = result;
	}
      else
	/* Deallocate the existing error message from a recursive
	   call, but reuse the result object.  */
	dl_action_result_errstring_free (result);
      result->errcode = errcode;
      result->objname = objname;
      result->errstring = (char *) errstring;
      result->returned = false;
      /* In case of an error, the malloced flag indicates whether the
	 error string is constant or not.  */
      if (malloced)
	result->errstring_source = dl_action_result_errstring_rtld;
      else
	result->errstring_source = dl_action_result_errstring_constant;
      return 1;
    }
}


int
_dl_catch_error (const char **objname, const char **errstring,
		 bool *mallocedp, void (*operate) (void *), void *args)
{
  struct dl_exception exception;
  int errorcode = _dl_catch_exception (&exception, operate, args);
  *objname = exception.objname;
  *errstring = exception.errstring;
  *mallocedp = exception.message_buffer == exception.errstring;
  return errorcode;
}


//rdi   rsi  rdx rcx
_dl_catch_exception (struct dl_exception *exception,
		     void (*operate) (void *), void *args)
{
 
  if (exception == NULL)
    {
      struct rtld_catch *old_catch = get_catch ();
      set_catch (NULL);
      operate (args);
      /* If we get here, the operation was successful.  */
      set_catch (old_catch);
      return 0;
    }
  /* We need not handle `receiver' since setting a `catch' is handled
     before it.  */
  /* Only this needs to be marked volatile, because it is the only local
     variable that gets changed between the setjmp invocation and the
     longjmp call.  All others are just set here (before setjmp) and read
     in _dl_signal_error (before longjmp).  */
  volatile int errcode;
  struct rtld_catch c;
  /* Don't use an initializer since we don't need to clear C.env.  */
  c.exception = exception;
  c.errcode = &errcode;
  struct rtld_catch *old = get_catch ();
  set_catch (&c);
  /* Do not save the signal mask.  */
  if (__builtin_expect (__sigsetjmp (c.env, 0), 0) == 0)
    {
      (*operate) (args);
      set_catch (old);
      *exception = (struct dl_exception) { NULL };
      return 0;
    }
  /* We get here only if we longjmp'd out of OPERATE.
     _dl_signal_exception has already stored values into
     *EXCEPTION.  */
  set_catch (old);
  return errcode;
}


//setjmp
0x7ffff7feb004 <__sigsetjmp+0004>    mov    QWORD PTR [rdi], rbx
   0x7ffff7feb007 <__sigsetjmp+0007> mov    rax, rbp
 → 0x7ffff7feb00a <__sigsetjmp+000a> xor    rax, QWORD PTR [rip+0x11a5f]        # 0x7ffff7ffca70 <__pointer_chk_guard_local>
   0x7ffff7feb011 <__sigsetjmp+0011> rol    rax, 0x11
   0x7ffff7feb015 <__sigsetjmp+0015> mov    QWORD PTR [rdi+0x8], rax
   0x7ffff7feb019 <__sigsetjmp+0019> mov    QWORD PTR [rdi+0x10], r12
   0x7ffff7feb01d <__sigsetjmp+001d> mov    QWORD PTR [rdi+0x18], r13
   0x7ffff7feb021 <__sigsetjmp+0021> mov    QWORD PTR [rdi+0x20], r14


struct dlopen_args
{
  /* The arguments for dlopen_doit.  */
  const char *file;
  int mode;
  /* The return value of dlopen_doit.  */
  void *new;
  /* Address of the caller.  */
  const void *caller;
};

dlopen_doit (void *a)
{
  struct dlopen_args *args = (struct dlopen_args *) a;
  if (args->mode & ~(RTLD_BINDING_MASK | RTLD_NOLOAD | RTLD_DEEPBIND
		     | RTLD_GLOBAL | RTLD_LOCAL | RTLD_NODELETE
		     | __RTLD_SPROF))
    _dl_signal_error (0, NULL, NULL, _("invalid mode parameter"));
  args->new = GLRO(dl_open) (args->file ?: "", args->mode | __RTLD_DLOPEN,
			     args->caller,
			     args->file == NULL ? LM_ID_BASE : NS,
			     __libc_argc, __libc_argv, __environ);
}

// file: rdi mod:rsi caller:rdx nsid:rcx  r8 r9 
void *
_dl_open (const char *file, int mode, const void *caller_dlopen, Lmid_t nsid,
	  int argc, char *argv[], char *env[])
{
  if ((mode & RTLD_BINDING_MASK) == 0)
    /* One of the flags must be set.  */
    _dl_signal_error (EINVAL, file, NULL, N_("invalid mode for dlopen()"));
  /* Make sure we are alone.  */
  __rtld_lock_lock_recursive (GL(dl_load_lock));
  if (__glibc_unlikely (nsid == LM_ID_NEWLM))
    {
      /* Find a new namespace.  */
      for (nsid = 1; DL_NNS > 1 && nsid < GL(dl_nns); ++nsid)
	if (GL(dl_ns)[nsid]._ns_loaded == NULL)
	  break;
      if (__glibc_unlikely (nsid == DL_NNS))
	{
	  /* No more namespace available.  */
	  __rtld_lock_unlock_recursive (GL(dl_load_lock));//lock
	  _dl_signal_error (EINVAL, file, NULL, N_("\
no more namespaces available for dlmopen()"));
	}
      else if (nsid == GL(dl_nns))
	{
	  __rtld_lock_initialize (GL(dl_ns)[nsid]._ns_unique_sym_table.lock);
	  ++GL(dl_nns);
	}
      GL(dl_ns)[nsid].libc_map = NULL;
      _dl_debug_update (nsid)->r_state = RT_CONSISTENT;
    }
  /* Never allow loading a DSO in a namespace which is empty.  Such
     direct placements is only causing problems.  Also don't allow
     loading into a namespace used for auditing.  */
  else if (__glibc_unlikely (nsid != LM_ID_BASE && nsid != __LM_ID_CALLER)
	   && (__glibc_unlikely (nsid < 0 || nsid >= GL(dl_nns))
	       /* This prevents the [NSID] index expressions from being
		  evaluated, so the compiler won't think that we are
		  accessing an invalid index here in the !SHARED case where
		  DL_NNS is 1 and so any NSID != 0 is invalid.  */
	       || DL_NNS == 1
	       || GL(dl_ns)[nsid]._ns_nloaded == 0
	       || GL(dl_ns)[nsid]._ns_loaded->l_auditing))
    _dl_signal_error (EINVAL, file, NULL,
		      N_("invalid target namespace in dlmopen()"));
  struct dl_open_args args;
  args.file = file;
  args.mode = mode;
  args.caller_dlopen = caller_dlopen;
  args.map = NULL;
  args.nsid = nsid;
  /* args.libc_already_loaded is always assigned by dl_open_worker
     (before any explicit/non-local returns).  */
  args.argc = argc;
  args.argv = argv;
  args.env = env;
  struct dl_exception exception;
  int errcode = _dl_catch_exception (&exception, dl_open_worker, &args); //dl catch exception
#if defined USE_LDCONFIG && !defined MAP_COPY
  /* We must unmap the cache file.  */
  _dl_unload_cache ();
#endif
  /* Do this for both the error and success cases.  The old value has
     only been determined if the namespace ID was assigned (i.e., it
     is not __LM_ID_CALLER).  In the success case, we actually may
     have consumed more pending adds than planned (because the local
     scopes overlap in case of a recursive dlopen, the inner dlopen
     doing some of the globalization work of the outer dlopen), so the
     old pending adds value is larger than absolutely necessary.
     Since it is just a conservative upper bound, this is harmless.
     The top-level dlopen call will restore the field to zero.  */
  if (args.nsid >= 0)
    GL (dl_ns)[args.nsid]._ns_global_scope_pending_adds
      = args.original_global_scope_pending_adds;
  /* See if an error occurred during loading.  */
  if (__glibc_unlikely (exception.errstring != NULL))
    {
      /* Avoid keeping around a dangling reference to the libc.so link
	 map in case it has been cached in libc_map.  */
      if (!args.libc_already_loaded)
	GL(dl_ns)[args.nsid].libc_map = NULL;
      /* Remove the object from memory.  It may be in an inconsistent
	 state if relocation failed, for example.  */
      if (args.map)
	{
	  _dl_close_worker (args.map, true);
	  /* All l_nodelete_pending objects should have been deleted
	     at this point, which is why it is not necessary to reset
	     the flag here.  */
	}
      /* Release the lock.  */
      __rtld_lock_unlock_recursive (GL(dl_load_lock));
      /* Reraise the error.  */
      _dl_signal_exception (errcode, &exception, NULL);
    }
  const int r_state __attribute__ ((unused))
    = _dl_debug_update (args.nsid)->r_state;
  assert (r_state == RT_CONSISTENT);
  /* Release the lock.  */
  __rtld_lock_unlock_recursive (GL(dl_load_lock));
  return args.map;
}
