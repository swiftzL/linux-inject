int
_dlerror_run (void (*operate) (void *), void *args)
{
  struct dl_action_result *result = __libc_dlerror_result;
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